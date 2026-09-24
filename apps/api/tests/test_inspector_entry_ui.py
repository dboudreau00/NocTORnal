"""The inspector and the create forms, as the 2026-09-22 review left them.

Findings from the ux05 (inspector) and ux06 (data entry) lenses, fixed on
2026-09-23 and held here by reading the shipped static assets and running
their pure functions under Node (skipped where Node is not installed). The
server halves are in `test_entity_entry_pg.py` (the pre-create check, the
selector recorded on create, the entity count, the ontology's inverse names
and selector types, selector dates) and `test_tie_review_pg.py`.

- why-below-metrics: Assertions and Evidence come before the numbers, and
  the metrics help is folded.
- positive-degree-called-vouches: "Positive ties", not "N vouches"; vouches
  by direction; the dyad rule said when the tie counts exceed Degree.
- first-last-seen-always-dash: the observed window from the live claims,
  said to be so; selector dates beside the count.
- grade-words-hover-only: the Admiralty grade printed in words.
- edge-type-note-stale: the chosen type read both ways, the permitted
  count on its own line.
- post-create-state: the outcome said in the inspector, under the name of
  the element it made (one note, gone when the analyst moves on; not a
  corner banner, which covered that name), the source cleared unless
  kept, the pane's messages dropped when it is left.
- valid-interval-shifts-day: the interval inputs say UTC.
- entity-list-no-find: a label filter, sortable columns, and pages of
  entities and of ties that say when they are not the whole case.
- selector-entities-bypass-normalisation and no-duplicate-check-on-create:
  the form asks before it creates; the merge panel lists likely matches
  first.
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


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    start = js.index(f"function {name}(")
    if js[start - 6:start] == "async ":
        start -= 6
    return js[start:js.index("\n}", start) + 2]


_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)

#: The shared date helpers, as test_ui_case_switch_and_dates.py lifts them.
def _dates() -> str:
    js = _js()
    return js[js.index("const MONTHS = ["):js.index("function fmtDay(")]


def _run(script: str) -> dict:
    if not NODE:
        pytest.skip("Node is not installed here")
    run = subprocess.run([NODE, "-"], input=script, capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


_HELPERS = """
function visibleText(s) { return String(s); }
function agree(n, one, many) { return n === 1 ? one : many; }
function countOf(n, one, many) { return n + ' ' + agree(n, one, many); }
"""


# ---------------------------------------------------------------------------
# ux05-inspector:why-below-metrics
# ---------------------------------------------------------------------------

def test_assertions_and_evidence_come_before_the_ties_and_the_numbers():
    html = _html()
    body = html[html.index('<div id="insp-body"'):]
    order = [body.index(f'id="{i}"') for i in (
        "insp-assertions", "insp-evidence", "insp-rel-sec", "insp-metrics-sec")]
    assert order == sorted(order), "the rail reads why before how many"


def test_the_metrics_help_is_folded():
    html = _html()
    sec = html[html.index('<section id="insp-metrics-sec"'):]
    sec = sec[:sec.index("</section>")]
    details = sec[sec.index('<details class="insp-more">'):sec.index("</details>")]
    assert "<summary>" in details and "These are <strong>local</strong>" in details


# ---------------------------------------------------------------------------
# ux05-inspector:positive-degree-called-vouches
# ---------------------------------------------------------------------------

def test_the_signed_rows_are_called_ties_not_vouches():
    body = _fn("renderNodeMetrics")
    assert "'Positive ties'" in body and "'Negative ties'" in body
    assert "'Positive degree'" not in body
    assert "el('div', 'metric-rank', 'vouches')" not in body
    assert "'Vouches received / given'" in body
    assert "vouchCounts(state.gedges, nodeId)" in body
    assert "dyadWords(row, state.metrics)" in body
    assert 'id="insp-metrics-dyad"' in _html()


def test_vouches_are_counted_by_direction_and_only_as_vouches():
    script = _HELPERS + "\n".join([
        _fn("asSentence"), _fn("vouchCounts"), _fn("dyadWords"),
        """const edges = [
  {edge_type: 'VOUCHED_FOR', src_node_id: 'q', dst_node_id: 'a'},
  {edge_type: 'VOUCHED_FOR', src_node_id: 'b', dst_node_id: 'q'},
  {edge_type: 'VOUCHED_FOR', src_node_id: 'c', dst_node_id: 'q'},
  {edge_type: 'COMMUNICATES_WITH', src_node_id: 'q', dst_node_id: 'd'},
  {edge_type: 'LEADS', src_node_id: 'd', dst_node_id: 'q'},
];
console.log(JSON.stringify({
  q: vouchCounts(edges, 'q'), d: vouchCounts(edges, 'd'),
  parallel: dyadWords({degree: 7, positive_degree: 9, negative_degree: 0},
                      {dyad_note: 'metrics treat the graph as simple: parallel edges between the same pair count once'}),
  simple: dyadWords({degree: 7, positive_degree: 6, negative_degree: 1}, null),
}));"""])
    got = _run(script)
    assert got["q"] == {"received": 2, "given": 1}
    assert got["d"] == {"received": 0, "given": 0}, "communication is not a vouch"
    assert got["parallel"].startswith("Degree counts neighbours (7 neighbours here). "
                                      "Metrics treat the graph as simple")
    assert "can exceed Degree" in got["parallel"]
    assert got["simple"] == "", "said only when the counts need reconciling"


# ---------------------------------------------------------------------------
# ux05-inspector:first-last-seen-always-dash
# ---------------------------------------------------------------------------

def test_the_observed_window_comes_from_live_claims_and_says_so():
    script = _dates() + "\n".join([
        _fn("observedWindow"), _fn("fmtWindow"), _fn("seenPhrase"),
        _fn("seenWords"), _fn("nodeSubLine"), _HELPERS,
        _fn("selectorSeenWords"),
        """const n = {id: 'n1', valid_from: null, valid_to: null};
const claims = [
  {observed_at: '2025-08-27T00:00:00Z'},
  {observed_at: '2026-01-02T00:00:00Z'},
  {observed_at: '2024-01-01T00:00:00Z', retracted_at: '2026-01-01T00:00:00Z'},
  {observed_at: null},
];
console.log(JSON.stringify({
  window: seenWords(n, claims),
  one: seenWords(n, [claims[0]]),
  loading: nodeSubLine(n, null),
  none: nodeSubLine(n, [{observed_at: null}]),
  server: seenWords({first_seen: '2025-08-27T00:00:00Z', last_seen: null}, null),
  sel3: selectorSeenWords({observation_cnt: 3, first_seen: '2025-08-27T00:00:00Z',
                           last_seen: '2026-01-02T10:15:00Z'}),
  sel1: selectorSeenWords({observation_cnt: 1, first_seen: '2025-08-27T00:00:00Z',
                           last_seen: '2025-08-27T00:00:00Z'}),
  sel0: selectorSeenWords({observation_cnt: 2}),
  timed: seenWords(n, [{observed_at: '2025-08-27T00:00:00Z'},
                       {observed_at: '2026-01-02T10:15:00Z'}]),
}));"""])
    got = _run(script)
    assert got["window"] == "observed 27 Aug 2025 to 2 Jan 2026 (from its claims)", (
        "a retracted claim's date is not part of the window")
    assert got["one"] == "observed 27 Aug 2025 (from its claims)"
    assert got["loading"] == "n1 · no validity interval recorded"
    assert got["none"] == ("n1 · no validity interval recorded · "
                           "no claim dates an observation")
    # Before the claims arrive, the server's window (gap-first-seen) in
    # seenPhrase's words: a lone end is one sighting, said once.
    assert got["server"] == "seen 27 Aug 2025"
    # One window, one format (the 2026-09-23 verifier: "27 Aug 2025 to
    # 2026-01-02 10:15 UTC" mixed a day with a time).
    assert got["sel3"] == ("observed 3 times, 2025-08-27 00:00 UTC to "
                           "2026-01-02 10:15 UTC")
    assert got["timed"] == ("observed 2025-08-27 00:00 UTC to 2026-01-02 "
                            "10:15 UTC (from its claims)")
    assert got["sel1"] == "observed once, 27 Aug 2025"
    assert got["sel0"] == "observed 2 times, no observation date recorded"


def test_the_sub_line_is_repainted_when_the_claims_arrive():
    body = _fn("renderInspector")
    assert "sub.textContent = nodeSubLine(n, null);" in body
    assert "if (sel.kind === 'node') paintSeen(sel.id, all);" in body
    assert "first seen ' + fmtWhen(n.first_seen)\n" not in body
    assert "selectorSeenWords(s)" in _fn("renderSelectors")


# ---------------------------------------------------------------------------
# ux05-inspector:grade-words-hover-only
# ---------------------------------------------------------------------------

def test_the_grade_is_printed_in_words():
    js = _js()
    consts = js[js.index("const RELIABILITY = {"):js.index("/* ICD 203 analytic confidence. */")]
    got = _run(consts + _fn("gradeWords") + """
console.log(JSON.stringify([gradeWords('C', '3'), gradeWords('F', 6),
                            gradeWords('A', '1'), gradeWords('Z', '9')]));""")
    assert got == [
        "source fairly reliable, information possibly true",
        "source reliability cannot be judged, truth cannot be judged",
        "source completely reliable, information confirmed by other sources",
        "source reliability not recorded, information credibility not recorded",
    ]
    assert "el('div', 'assert-grade',\n      gradeWords(a.reliability, a.credibility))" \
        in _fn("renderAssertions")


# ---------------------------------------------------------------------------
# ux06-entry:edge-type-note-stale
# ---------------------------------------------------------------------------

def test_the_chosen_type_is_read_both_ways_with_its_sign():
    got = _run(_fn("signWords") + _fn("edgeTypeWords") + """
const alias = {display_name: 'is an alias of', inverse_name: 'has alias',
               default_sign: 0, is_social_tie: false};
const scam = {display_name: 'accused of ripping', inverse_name: 'was accused by',
              default_sign: -1, is_social_tie: true};
const peers = {display_name: 'communicates with', inverse_name: 'communicates with',
               default_sign: 1, is_social_tie: true};
const a = {label: 'harrow_skua2'}, b = {label: 'ferric_auk98'};
console.log(JSON.stringify([edgeTypeWords(alias, a, b), edgeTypeWords(scam, a, b),
                            edgeTypeWords(peers, a, b)]));""")
    assert got[0] == ("harrow_skua2 is an alias of ferric_auk98. Read the other "
                      "way: ferric_auk98 has alias harrow_skua2. It is neutral "
                      "(sign 0), not counted as a social tie, so the All ties "
                      "view leaves it out.")
    assert got[1].endswith("It is a NEGATIVE tie, counted as a social tie.")
    assert "Read the other way" not in got[2], "a symmetric name is said once"


def test_the_permitted_count_is_its_own_line():
    assert 'id="edge-type-count"' in _html()
    body = _fn("describeEdgeType")
    assert "$('edge-type-count').textContent = permitted + ' permitted for '" in body
    assert "edgeTypeWords(chosen" in body
    assert "$('edge-type-count').textContent = '';" in _fn("refreshEdgeTypes")


# ---------------------------------------------------------------------------
# ux06-entry:post-create-state
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fn,prefix", [("createNode", "node"), ("createEdge", "edge")])
def test_the_outcome_is_said_on_the_element_and_the_source_is_not_inherited(
        fn, prefix):
    body = _fn(fn)
    assert f"createdWords('{prefix}'" in body
    assert f"noteCreated('{prefix}', out.id," in body
    assert "setMsg(okBox, assertion.evidence_id" not in body, (
        "a status line written and hidden in the same moment is never read")
    # The second round (the 2026-09-23 verifier): the corner banner stack
    # sat over the inspector's title, stacked per entry, took the error
    # edge for a success and outlived a case switch.
    assert "banner(" not in body, "the outcome is not a corner banner"
    assert f"resetAfterCreate('{prefix}');" in body
    assert f'id="{prefix}-keep-source" type="checkbox"' in _html()


def test_the_outcome_sits_under_the_elements_name_in_the_rails_flow():
    html = _html()
    body = html[html.index('<div id="insp-body"'):]
    sub = body.index('<p id="insp-sub"')
    note = body.index('<div id="insp-created" class="insp-created" role="status" hidden>')
    assert sub < note < body.index('<div id="insp-actions"'), (
        "under the name it is about, above everything else in the rail")
    assert 'id="insp-created-close" type="button"' in body
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    rule = css[css.index(".insp-created {"):]
    rule = rule[:rule.index("}")]
    assert "position" not in rule, "in the flow, never over the name"
    assert "border-left: 2px solid var(--accent)" in rule
    assert ".insp-created.warn { border-left-color: var(--alert);" in css
    assert "syncCreatedNote(sel);" in _fn("renderInspector")
    assert "wireCreatedNote();" in _js()
    js = _js()
    switch = js[js.index("function wireCreatedNote()"):]
    switch = switch[:switch.index("});\n", switch.index("onCaseSwitch(")) + 4]
    assert "dropCreatedNote();" in switch.split("onCaseSwitch(")[1], (
        "a case switch takes it away")


def test_the_outcome_is_one_note_that_goes_when_the_analyst_moves_on():
    got = _run(_fn("createdNoteFate") + """
const note = {key: 'node:n1', lines: ['x'], warn: true, seen: false};
const fates = [];
fates.push(createdNoteFate(note, {kind: 'node', id: 'old'}));  // reload repaint
fates.push(createdNoteFate(note, {kind: 'node', id: 'n1'}));   // selected
note.seen = true;
fates.push(createdNoteFate(note, {kind: 'node', id: 'n1'}));   // repainted
fates.push(createdNoteFate(note, {kind: 'edge', id: 'n1'}));   // moved on
fates.push(createdNoteFate(note, null));                         // cleared
fates.push(createdNoteFate({key: null}, {kind: 'node', id: 'n1'}));
console.log(JSON.stringify(fates));""")
    assert got == ["wait", "show", "show", "drop", "drop", "drop"]
    # One note at a time: a new create replaces it rather than stacking.
    note = _fn("noteCreated")
    assert "createdNote.lines = lines;" in note and "push(" not in note


def test_the_source_goes_together_unless_kept():
    reset = _fn("resetAfterCreate")
    assert "for (const f of ['rationale', 'valid-from', 'valid-to'])" in reset
    assert "if (!$(prefix + '-keep-source').checked)" in reset
    assert "for (const f of ['evidence', 'observed', 'ref'])" in reset
    for prefix in ("node", "edge"):
        assert f"'{prefix}-keep-source'" in _fn("adoptCaseInCreateForms")
    got = _run(_fn("createdWords") + _fn("selectorHeldWords") + """
console.log(JSON.stringify([createdWords('node', false, false),
                            createdWords('edge', true, true),
                            selectorHeldWords('JABBER', 'vendor', true)]));""")
    assert got[0].startswith("Entity created, with its founding assertion, "
                             "and it has NO exhibit behind it yet")
    assert got[1].startswith("Relationship recorded, with its founding "
                             "assertion and exhibit.")
    assert "kept for the next entry" in got[1]
    assert got[2].startswith("This JABBER was already recorded against vendor")
    assert "a merge lead" in got[2]


def test_a_create_panes_messages_go_when_it_is_left():
    body = _fn("watchCreatePanes")
    assert "new MutationObserver(" in body
    assert "attributeFilter: ['hidden']" in body
    assert "if (wasOpen && !open)" in body, "on leaving, not on every re-hide"
    assert "watchCreatePanes();" in _js()


# ---------------------------------------------------------------------------
# ux06-entry:valid-interval-shifts-day
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("prefix", ["node", "edge"])
def test_the_interval_inputs_say_utc(prefix):
    html = _html()
    for end, word in (("from", "From"), ("to", "Until")):
        block = html[:html.index(f'id="{prefix}-valid-{end}"')]
        label = block[block.rindex('<span class="label">'):]
        assert f"{word} (UTC day)" in label
    fieldset = html[html.index(f'id="{prefix}-valid-from"'):]
    assert "Dates are calendar days in UTC" in fieldset[:fieldset.index("</fieldset>")]


# ---------------------------------------------------------------------------
# ux06-entry:entity-list-no-find
# ---------------------------------------------------------------------------

def test_the_list_has_a_label_filter_and_sortable_headers():
    html = _html()
    pane = html[html.index('<section id="pane-entities"'):]
    pane = pane[:pane.index("</section>")]
    assert 'id="ent-find" type="search"' in pane
    for key in ("type", "label", "classification", "first_seen"):
        assert re.search(r'<th scope="col" data-sort="' + key
                         + r'" aria-sort="none"><button type="button" class="th-sort">',
                         pane), key
    assert "wireEntityList();" in _js()
    load = _fn("loadCaseGraph")
    assert "refreshEntityTotal();" in load
    assert "'/edges?limit=' + EDGE_PAGE" in load
    refresh = _fn("refreshEntityTotal")
    assert "cpath('/graph/nodes/count')" in refresh
    assert "state.edges.length < EDGE_PAGE" in refresh, (
        "a full tie page asks for the total too")
    assert "entityList.edgeTotal = out.edges;" in refresh


def test_filtering_sorting_and_the_count_line():
    script = _HELPERS + "\n".join([
        "const TLP = ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED'];",
        "function typeName(k) { return {IDENTITY: 'Persona', WALLET: 'Crypto wallet'}[k] || k; }",
        _fn("entityRows"), _fn("sortEntityRows"), _fn("entityCountWords"),
        """const nodes = [
  {label: 'vendor10', node_type: 'IDENTITY', classification: 'RED', first_seen: null},
  {label: 'Vendor2', node_type: 'IDENTITY', classification: 'AMBER', first_seen: '2025-01-02T00:00:00Z'},
  {label: 'bc1qvendor', node_type: 'WALLET', classification: 'GREEN', first_seen: '2024-01-02T00:00:00Z'},
];
const labels = (rows) => rows.map((n) => n.label);
console.log(JSON.stringify({
  find: labels(entityRows(nodes, '', 'VEND 2')),
  typed: labels(entityRows(nodes, 'WALLET', 'vendor')),
  byLabel: labels(sortEntityRows(nodes, 'label', 1)),
  byLabelDown: labels(sortEntityRows(nodes, 'label', -1)),
  byClass: labels(sortEntityRows(nodes, 'classification', 1)),
  bySeen: labels(sortEntityRows(nodes, 'first_seen', 1)),
  bySeenDown: labels(sortEntityRows(nodes, 'first_seen', -1)),
  unsorted: labels(sortEntityRows(nodes, null, 1)),
  whole: entityCountWords(2, 146, null, 492, null),
  page: entityCountWords(12, 1000, 1432, 1000, 1000),
  ties: entityCountWords(146, 146, 146, 1000, 1204),
}));"""])
    got = _run(script)
    assert got["find"] == ["Vendor2"], "every word must appear"
    assert got["typed"] == ["bc1qvendor"]
    assert got["byLabel"] == ["bc1qvendor", "Vendor2", "vendor10"], "numerals as numbers"
    assert got["byLabelDown"] == ["vendor10", "Vendor2", "bc1qvendor"]
    assert got["byClass"] == ["bc1qvendor", "Vendor2", "vendor10"]
    assert got["bySeen"] == ["bc1qvendor", "Vendor2", "vendor10"]
    assert got["bySeenDown"][-1] == "vendor10", "an absent date sorts last either way"
    assert got["unsorted"] == ["vendor10", "Vendor2", "bc1qvendor"]
    assert got["whole"] == "2 of 146 entities · 492 relationships in the case"
    assert got["page"].startswith("12 listed from the newest 1000 of 1432 entities")
    assert got["page"].endswith("· 1000 relationships in the case")
    # The tie page stops at 1000 too, and said "1000 relationships" of a
    # larger case (the 2026-09-23 verifier).
    assert got["ties"] == ("146 of 146 entities · 1204 relationships in the "
                           "case (only the newest 1000 are loaded)")


# ---------------------------------------------------------------------------
# ux06-entry:selector-entities-bypass-normalisation
# ux06-entry:no-duplicate-check-on-create
# ---------------------------------------------------------------------------

def test_the_selector_picker_exists_and_every_offered_type_is_real():
    from noctornal_ontology import SELECTOR_TYPES
    html = _html()
    assert 'id="node-sel-type-field" hidden' in html
    assert 'id="node-check" class="node-check" role="status"' in html
    js = _js()
    table = js[js.index("const SELECTOR_TYPES_FOR = {"):]
    table = table[:table.index("};")]
    known = {s.key for s in SELECTOR_TYPES}
    offered = set(re.findall(r"'([A-Z0-9_]+)'", table))
    assert offered and offered <= known, offered - known
    assert "new Set(['SELECTOR', 'COMMS_ACCOUNT', 'WALLET'])" in js
    from noctornal_api.http.routers.graph import SELECTOR_NODE_TYPES
    assert SELECTOR_NODE_TYPES == {"SELECTOR", "COMMS_ACCOUNT", "WALLET"}


def test_an_entity_the_index_has_no_type_for_can_still_be_made():
    """A wallet on a chain the ontology has no selector type for is a real
    entity. The picker offers "None of these" explicitly, which sends no
    selector type, so the form never blocks it and never skips the index by
    default: the placeholder is not an answer."""
    got = _run("""
const vals = {'node-type': 'WALLET', 'node-sel-type': ''};
function $(id) { return { get value() { return vals[id]; } }; }
""" + "\n".join([
        "const SELECTOR_ENTITY_TYPES = new Set(['SELECTOR', 'COMMS_ACCOUNT', 'WALLET']);",
        "const NOT_INDEXED = 'not-indexed';",
        _fn("selectorTypeWanted"), _fn("selectorAnswered"),
        """const out = {};
out.placeholder = [selectorAnswered(), selectorTypeWanted()];
vals['node-sel-type'] = 'not-indexed';
out.none = [selectorAnswered(), selectorTypeWanted()];
vals['node-sel-type'] = 'BTC_ADDR';
out.btc = [selectorAnswered(), selectorTypeWanted()];
vals['node-type'] = 'IDENTITY'; vals['node-sel-type'] = '';
out.persona = [selectorAnswered(), selectorTypeWanted()];
console.log(JSON.stringify(out));"""]))
    assert got == {"placeholder": [False, ""], "none": [True, ""],
                   "btc": [True, "BTC_ADDR"], "persona": [True, ""]}
    assert "[NOT_INDEXED, 'None of these (not indexed, not checked)']" in _fn(
        "syncSelectorType")


def test_the_form_asks_before_it_creates():
    body = _fn("createNode")
    assert body.index("await runNodeCheck()") < body.index("await api(cpath('/nodes')")
    assert body.index("if (!selectorAnswered())") < body.index("await api(")
    assert "nodeCheckProblem(checked, false, selType," in body
    assert "selector_type: selType || null" in body
    assert "out.selector_owner_id" in body, "a merge lead is said"
    check = _fn("runNodeCheck")
    assert "api(cpath('/graph/nodes/check'), {\n      method: 'POST'" in check, (
        "a label is case content: never in a URL")
    assert "seq !== nodeCheck.seq" in check and "caseChanged(token)" in check
    wire = _fn("wireNodeCheck")
    for element_id in ("node-label", "node-type", "node-sel-type"):
        assert f"$('{element_id}').addEventListener(" in wire


def test_what_holds_a_create_back():
    got = _run(_fn("asSentence") + _fn("nodeCheckProblem") + """
const refused = {same_label: [], selector_refusal: "'123' cannot be reduced"};
const dup = {same_label: [{id: 'n1', label: 'harrow_skua2', node_type: 'IDENTITY'}]};
const owner = {same_label: [], selector_owner: {id: 'n2'}};
console.log(JSON.stringify({
  noType: nodeCheckProblem(null, true, '', false),
  refused: nodeCheckProblem(refused, false, 'TELEGRAM_ID', true),
  dup: nodeCheckProblem(dup, false, '', false),
  dupAcked: nodeCheckProblem(dup, false, '', true),
  owner: nodeCheckProblem(owner, false, 'JABBER', false),
  failedCheck: nodeCheckProblem(null, false, '', false),
  clean: nodeCheckProblem({same_label: []}, false, '', false),
}));""")
    assert "Choose what kind of selector" in got["noType"]
    assert "None of these" in got["noType"], "the way out is named"
    assert got["refused"].startswith("Not a usable TELEGRAM_ID: '123' cannot"), (
        "a refusal is never waved through, acknowledged or not")
    assert "Create anyway" in got["dup"] and "Create anyway" in got["owner"]
    assert got["dupAcked"] is None
    assert got["failedCheck"] is None, "an advisory read that failed blocks nothing"
    assert got["clean"] is None


def test_the_merge_panel_lists_likely_matches_first():
    got = _run(_fn("mergeKey") + _fn("mergeCandidates") + """
const me = {id: 'a', label: 'harrow_skua2', node_type: 'IDENTITY'};
const nodes = [me,
  {id: 'b', label: 'aardvark', node_type: 'IDENTITY'},
  {id: 'c', label: 'Harrow Skua 2', node_type: 'IDENTITY'},
  {id: 'd', label: 'HARROW-SKUA2', node_type: 'IDENTITY'},
  {id: 'e', label: 'harrow_skua2', node_type: 'PERSON'}];
const out = mergeCandidates(me, nodes);
console.log(JSON.stringify({likely: out.likely.map((n) => n.id),
                            rest: out.rest.map((n) => n.id)}));""")
    assert sorted(got["likely"]) == ["c", "d"]
    assert got["rest"] == ["b"], "another type is never a merge candidate"
    assert "Likely the same (the label matches)" in _fn("renderMergePanel")


def test_the_new_copy_carries_no_dash_a_reader_sees():
    js = _js()
    for start, end in (("/* ── Add entity: is it already here", "async function createNode("),
                       ("/* ux06-entry:entity-list-no-find", "function renderEntities()"),
                       ("/* ── when an entity was observed", "function renderInspector()")):
        region = js[js.index(start):js.index(end)]
        code = re.sub(r"/\*.*?\*/", "", region, flags=re.S)
        assert "\u2014" not in code and "\u2013" not in code and " -- " not in code, start
