"""The Triage pane, held to the Alpha 6 release review (2026-09-24).

Pure: the shipped static assets, with the real functions run under Node
against stubs (skipped where Node is absent), beside test_ui_invariants.
The server halves are in test_triage_release_review_pg.py. Each test
fails on d0faa34 and names the finding it holds:

- c14: the keys' cursor was a bare index, so after a live reload A, R and
  D acted on a card the analyst never picked, and the dialogs did not
  name it.
- c1: a card whose Accept the server refuses said TLP:RED and offered it.
- c15: the capture form offered every level, reset to AMBER on every case.
- u2: a read-only case badged proposals and feed records nobody may clear.
- u11: the Undo was offered to a REVIEWER, whose role cannot retire.
"""
from __future__ import annotations

import json

from test_ui_triage_inbox import (
    _TRIAGE_PAGE,
    _const,
    _css,
    _fn,
    _html,
    _js,
    _run,
    _visible,
    needs_node,
)

#: The real card helpers the dialogs name a proposal with.
_NAMING = ["triageRefName", "triageTitle", "triageClaimValue", "triageNamed"]

N1 = "899b2ae7-1a22-4ddc-9270-7727b02181ef"
ATTR = (f"{{ id: 'a1', kind: 'ATTRIBUTE', state: 'PROPOSED', "
        f"classification: 'RED', payload: {{ node_id: '{N1}', "
        f"claim_path: 'comms.XMPP', claim_value: 'kite@xmpp.example' }}, "
        f"refs: {{ '{N1}': {{ label: 'g18rev publisher', node_type: 'IDENTITY' }} }} }}")


# ---------------------------------------------------------------------------
# c14: the cursor is a proposal, not a position
# ---------------------------------------------------------------------------

@needs_node
def test_the_cursor_follows_the_picked_card_across_a_live_reload(tmp_path):
    """The verifier's reproduction: pick the second card, a colleague's
    capture lands a higher-scored one above it, and the reload kept the
    index, so the keys moved to the newcomer."""
    got = _run([_fn("renderTriage"), _fn("pickTriageCard"),
                _fn("triageSourceLine"), _fn("triageKeyTarget"),
                _fn("onTriageKey")], _TRIAGE_PAGE + """
const acted = [];
function acceptProposal(p) { acted.push(['accept', p.id]); }
function rejectProposal(p) { acted.push(['reject', p.id]); }
function deferProposal(p) { acted.push(['defer', p.id]); }
function anyDialogOpen() { return false; }
function triageLettersOn() { return true; }
function triageAcceptQuestion(p) { return 'Accept ' + p.id + '?'; }
const asked = [];
window.confirm = (q) => { asked.push(q); return true; };
state.tab = 'triage';
const card = (id) => ({ id, kind: 'NODE', state: 'PROPOSED', payload: {} });
state.triage = [card('p1'), card('p2')];
renderTriage();
const box = nodes['triage-list'];
box.children[1].listeners.click();
const out = { picked: [state.triageIndex, state.triageId] };

// A colleague's capture: a new card scored above both, and a live reload.
state.triage = [card('new'), card('p1'), card('p2')];
renderTriage();
out.afterReload = [state.triageIndex, state.triageId,
  box.children.map((c) => c.className.split(' ').includes('on'))];
// The key lands on the highlighted card, as the focus follows it.
const key = (k) => {
  const on = box.children[state.triageIndex] || box.children[0];
  on.classList._s.add('triage-card');
  onTriageKey({ key: k, target: on, preventDefault() {} });
};
key('r'); key('a');
out.acted = acted.splice(0);
out.asked = asked.splice(0);

// The picked card leaves (accepted elsewhere): the nearest one left is it.
state.triage = [card('new'), card('p1')];
renderTriage();
out.afterLeave = [state.triageIndex, state.triageId];

// A picked card gone without a rebuild is acted on by nobody, and a
// position past the end no longer throws.
state.triageId = 'gone';
key('r'); key('d'); key('a');
state.triageId = null; state.triageIndex = 7;
key('r');
out.gone = acted.splice(0);
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["picked"] == [1, "p2"]
    assert got["afterReload"] == [2, "p2", [False, False, True]], (
        "the reload kept the position and moved the keys to another card")
    assert got["acted"] == [["reject", "p2"], ["accept", "p2"]]
    assert got["asked"] == ["Accept p2?"]
    assert got["afterLeave"] == [1, "p1"]
    assert got["gone"] == [], "a key acted on a card the analyst never picked"


@needs_node
def test_every_verdict_dialog_names_the_card_it_acts_on(tmp_path):
    """The A confirm read 'Accept "this suggestion" (ATTRIBUTE)' for an
    ATTRIBUTE or EDGE card, and R and D named nothing."""
    got = _run([_fn(n) for n in _NAMING] + [
        _fn("triageAcceptQuestion"), _fn("rejectProposal"), _fn("deferProposal"),
        _const("CASE_STATES_SHUT"), _fn("caseReadOnly")], """
const state = { caseRec: { status: 'ACTIVE', read_only: false } };
const prompts = [];
const window = { prompt(q) { prompts.push(q); return null; } };
function banner() {}
function disposition() {}
const attr = """ + ATTR + """;
const node = { id: 'n1', kind: 'NODE', classification: 'AMBER',
               payload: { label: 'spectre.lynx@protonmail.com' } };
rejectProposal(attr); deferProposal(node);
console.log(JSON.stringify({ accept: triageAcceptQuestion(attr), prompts }));
""", tmp_path)
    said = ('"g18rev publisher (Identity) gains comms.XMPP" with the value '
            'kite@xmpp.example (ATTRIBUTE, TLP:RED)')
    assert got["accept"].startswith("Accept " + said + " into the graph?")
    assert "this suggestion" not in got["accept"]
    assert got["prompts"][0].startswith("Reject " + said + "?")
    assert got["prompts"][1].startswith(
        'Defer "spectre.lynx@protonmail.com" (NODE, TLP:AMBER)?')


def test_every_reset_of_the_index_resets_the_id_too():
    js = _js()
    assert "triageId: null," in js
    switch = js[js.index("onCaseSwitch(() => {\n  state.triage = [];"):]
    switch = switch[:switch.index("\n});")]
    assert "state.triageId = null;" in switch
    change = js[js.index("$('triage-state').addEventListener('change'"):]
    assert "state.triageId = null;" in change[:change.index("});")]
    # openCase's own reset too (the verifier of the fix round): harmless
    # while the switch handler clears it, and one rule is easier to keep.
    opened = _fn("openCase")
    assert "state.triageIndex = 0;\n  state.triageId = null;" in opened


# ---------------------------------------------------------------------------
# c1: a claim the server refuses to attach is not offered
# ---------------------------------------------------------------------------

@needs_node
def test_a_blocked_claim_says_why_and_offers_no_accept(tmp_path):
    reason = ("This claim was found in RED material in compartment X, and the "
              "entity it would be attached to is labelled CLEAR with no "
              "compartments.")
    got = _run([_fn("triageActions"), _fn("triageCanUndo"), _fn("caseCan"),
                _const("TRIAGE_UNDO_PERMISSION"), _fn("acceptProposal"),
                _const("CASE_STATES_SHUT"), _fn("caseReadOnly"),
                _fn("renderTriage"), _fn("pickTriageCard"),
                _fn("triageSourceLine")], _TRIAGE_PAGE.replace(
                    "function triageActions() { return el('div', 'triage-actions'); }\n",
                    "") + """
state.caseRec = { status: 'ACTIVE', read_only: false };
const banners = [], sent = [];
function banner(t, d) { banners.push([t, d]); }
function disposition(p) { sent.push(p.id); }
function rejectProposal() {} function deferProposal() {}
function triageChosenLevel() { return null; }
const p = { id: 'b1', kind: 'ATTRIBUTE', state: 'PROPOSED', payload: {},
            accept_blocked: """ + json.dumps(reason) + """ };
const acts = triageActions(p);
const accept = acts.children.find((b) => b.textContent === 'Accept');
acceptProposal(p);
state.triage = [p];
renderTriage();
const drawn = nodes['triage-list'].children[0].children
  .filter((c) => c.className.includes('triage-blocked')).map((c) => c.textContent);
console.log(JSON.stringify({ disabled: accept.disabled, title: accept.title,
  banners, sent, drawn }));
""", tmp_path)
    assert got["disabled"] is True and got["title"] == reason
    assert got["sent"] == [], "a refused claim was sent to the server anyway"
    assert got["banners"] == [["Not accepted", reason]]
    assert got["drawn"] == [reason + " Reject or defer it."]
    # Styled beside the card's other lines, as a warning.
    assert ".triage-blocked {" in _css()
    assert "'msg warn triage-blocked'" in _fn("renderTriage")


# ---------------------------------------------------------------------------
# c15: the capture form is fitted to the case
# ---------------------------------------------------------------------------

_CAPTURE_PAGE = r"""
const nodes = {};
function $(id) { return nodes[id] || (nodes[id] = el('x')); }
nodes['cap-class'] = Object.assign(el('select'), { value: '' });
function opts(select, pairs, selected) {
  select.children = pairs.map(([v]) => v);
  select.value = pairs.some(([v]) => v === selected) ? selected : pairs[0][0];
}
function setMsg(n, t) { n.textContent = t || ''; n.hidden = !t; }
"""


@needs_node
def test_the_capture_form_starts_at_the_case_and_offers_nothing_below(tmp_path):
    got = _run([_fn("syncCaptureForm")], _CAPTURE_PAGE + """
const out = {};
const sel = $('cap-class'), btn = $('cap-run'), note = $('cap-scope');
note.hidden = true;
const look = () => [sel.children.slice(), sel.value, btn.disabled, note.hidden];
const halcyon = { id: 'halcyon', classification: 'RED' };
const nightjar = { id: 'nightjar', classification: 'AMBER' };
const kestrel = { id: 'kestrel', classification: 'GREEN' };
syncCaptureForm(null, ''); out.none = look();
syncCaptureForm(halcyon); out.red = look();
syncCaptureForm(nightjar); syncCaptureForm(nightjar, ''); out.amber = look();
sel.value = 'RED';
syncCaptureForm(nightjar); syncCaptureForm(nightjar, '');
out.kept = sel.value;
syncCaptureForm(kestrel);
out.otherCase = sel.value;
syncCaptureForm(halcyon, 'Capture is off on this case. It is kept in compartment X.');
out.scoped = [btn.disabled, note.hidden, note.textContent];
syncCaptureForm(kestrel, '');
out.freed = btn.disabled;
// A live reload mid-capture must not free the button the capture holds.
btn.disabled = true;
syncCaptureForm(kestrel); syncCaptureForm(kestrel, '');
out.heldDuringCapture = btn.disabled;
syncCaptureForm(null, '');
out.switched = btn.disabled;
console.log(JSON.stringify(out));
""", tmp_path)
    tlp = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"]
    assert got["none"] == [tlp, "AMBER", False, True]
    assert got["red"] == [["RED"], "RED", False, True], (
        "a RED case's capture form offered AMBER")
    assert got["amber"] == [["AMBER", "AMBER_STRICT", "RED"], "AMBER", False, True]
    assert got["kept"] == "RED", "a live reload threw away the analyst's choice"
    assert got["otherCase"] == "GREEN"
    assert got["scoped"] == [
        True, False, "Capture is off on this case. It is kept in compartment X."]
    assert got["freed"] is False
    assert got["heldDuringCapture"] is True
    assert got["switched"] is False, "a case switch left the button held"


def test_the_case_switch_and_every_load_fit_the_capture_form():
    js = _js()
    load = _fn("loadTriage")
    assert "syncCaptureForm(state.caseRec);" in load
    assert "state.captureRefused = data.capture_refused || '';" in load
    assert "syncCaptureForm(state.caseRec, state.captureRefused);" in load
    assert "$('cap-class').value = 'AMBER';" not in js
    run = _fn("runCapture")
    assert "if (state.captureRefused) {" in run, "a compartmented case still captures"
    assert "captureLabelWords(out)" in run
    html = _html()
    assert 'id="cap-scope"' in html
    flat = " ".join(_visible(html).split())
    assert "never below the case's own" in flat
    assert "keeps the label it was first stored at" in flat


@needs_node
def test_a_capture_reply_says_whose_label_is_whose_and_names_none_above(tmp_path):
    """The fix round (2026-09-24): a re-paste leaves the shared document at
    its earlier label, so "Stored at" is said only when the document and
    the proposals agree; a label above the analyst comes back null and the
    line names none."""
    got = _run([_fn("captureLabelWords")], """
console.log(JSON.stringify([
  captureLabelWords({ classification: 'RED', document_classification: 'RED' }),
  captureLabelWords({ deduplicated: true, classification: 'RED',
                      document_classification: 'AMBER' }),
  captureLabelWords({ deduplicated: true, classification: null,
                      document_classification: null }),
  captureLabelWords({}),
]));
""", tmp_path)
    fresh, repaste, above, none = got
    assert fresh == "Stored at TLP:RED. "
    assert repaste == ("An earlier capture stored this text at TLP:AMBER, and "
                       "it stays at that label. Its proposals here carry "
                       "TLP:RED. ")
    assert "TLP:" not in above and "above your clearance" in above
    assert none == ""


# ---------------------------------------------------------------------------
# u2: a read-only case waits for nobody
# ---------------------------------------------------------------------------

@needs_node
def test_a_read_only_case_badges_nothing_nobody_can_clear(tmp_path):
    got = _run([_fn("renderTriageBadge"), _fn("triageBadgeTitle"),
                _fn("paintFeedsBadge"), _fn("repaintWorkBadges"),
                _const("CASE_STATES_SHUT"),
                _fn("caseReadOnly")], """
const nodes = {};
function $(id) { return nodes[id] || (nodes[id] = el('x')); }
function show(n, on) { n.hidden = !on; }
const state = { caseId: 'c', triageCounts: { PROPOSED: 2 }, waiting: {},
                caseRec: { code: 'OP-X', status: 'ACTIVE', read_only: false } };
const out = {};
renderTriageBadge(); paintFeedsBadge({ watched_untriaged: 3 });
out.open = [$('triage-badge').hidden, $('feeds-badge').hidden];
state.caseRec = { code: 'OP-X', status: 'CLOSED', read_only: true };
renderTriageBadge(); paintFeedsBadge({ watched_untriaged: 3 });
out.closed = [$('triage-badge').hidden, $('feeds-badge').hidden];
// Closed in another tab: only the record is re-read, and the badges that
// were painted while it was open are repainted from it.
state.caseRec = { code: 'OP-X', status: 'ACTIVE', read_only: false };
renderTriageBadge(); paintFeedsBadge({ watched_untriaged: 3 });
state.caseRec = { code: 'OP-X', status: 'CLOSED', read_only: true };
repaintWorkBadges();
out.closedElsewhere = [$('triage-badge').hidden, $('feeds-badge').hidden];
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["open"] == [False, False]
    assert got["closed"] == [True, True], (
        "a closed case kept badges that no disposition may clear")
    assert got["closedElsewhere"] == [True, True], (
        "a case closed in another tab kept its badges")
    assert "repaintWorkBadges();" in _fn("caseTurnedReadOnly")


# ---------------------------------------------------------------------------
# u11: the Undo is offered only to a role that can retire
# ---------------------------------------------------------------------------

@needs_node
def test_a_reviewer_is_not_offered_an_undo_that_can_only_fail(tmp_path):
    got = _run([_fn(n) for n in _NAMING] + [
        _fn("showTriageOutcome"), _fn("triageChosenLevel"), _fn("triageCanUndo"),
        _fn("caseCan"), _const("TRIAGE_UNDO_PERMISSION"),
        _const("TRIAGE_UNDO_WORDS"), _fn("triageActions")], """
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
const line = el('p', 'msg');
function $() { return line; }
function undoAccept() {}
function acceptProposal() {} function rejectProposal() {} function deferProposal() {}
const reviewer = { my_role: 'REVIEWER', my_permissions: ['case.read', 'proposal.review'] };
const owner = { my_role: 'CASE_OWNER', my_permissions: ['case.read',
  'proposal.review', 'graph.node.delete', 'graph.edge.delete', 'assertion.retract'] };
const state = { triageAcceptAt: {}, caseRec: reviewer };
const node = { id: 'n1', kind: 'NODE', payload: { label: 'x' } };
const attr = { id: 'a1', kind: 'ATTRIBUTE', payload: { node_id: 'q', claim_path: 'comms.tox' } };
const texts = () => line.children.map((c) => c.textContent);
const tip = (p) => triageActions(p).children.find((b) => b.textContent === 'Accept').title;
const out = {};
showTriageOutcome(node, 'accept', {}); out.reviewer = texts();
out.reviewerTip = tip(attr);
showTriageOutcome(attr, 'accept', {}); out.reviewerAttr = texts();
state.caseRec = owner;
showTriageOutcome(attr, 'accept', {}); out.owner = texts();
out.ownerTip = tip(attr);
console.log(JSON.stringify(out));
""", tmp_path)
    assert "Undo" not in got["reviewer"], "a REVIEWER was offered an Undo"
    assert "cannot retire it, so there is no Undo" in got["reviewer"][1]
    assert "retire entities" in got["reviewer"][1]
    assert "retract claims" in got["reviewerAttr"][1]
    assert "no Undo follows" in got["reviewerTip"]
    assert got["owner"][-1] == "Undo"
    assert "An Undo appears above the queue." in got["ownerTip"]


def test_the_help_promises_the_undo_only_where_a_role_can_retire():
    flat = " ".join(_visible(_html()).split())
    assert "offers an Undo when your role can retire it" in flat
    assert "Undo retires it where your role can" in flat
    assert "Each question names the suggestion it acts on" in flat
