"""No count in the console is hedged with a bracketed plural.

The README screenshot set review (2026-09-23) found a bracketed "s" after
counts the console already knew, in the final frames: one request on the
approvals list, two claims on the comms pane, six connected components in
the analysis cohesion line (beside "1 communities", the same fault without
the brackets). The reviewers listed about thirty more sites. A reader does
the agreement the line should have done, and it reads as unfinished.

The rule: no string literal and no run of template text in `app.js`, and
nothing a reader sees in `index.html`, holds a bracketed plural ending
(s, es, ies, y/ies, is/es). The console agrees a count with `countOf`, and
a verb or a noun printed apart from its count with `agree`; the checks
marked `needs_node` run the rewritten lines under Node and read what they
say, for one and for many.

The JavaScript lexer is `test_ui_copy_no_dashes.py`'s, which is proved
there on known input and against every dash in the file. Comments and
regular expressions are skipped for the reason given there.

The allow-list has one entry: renderRedaction's fallback line for a
report whose server sent no statement. The report statement code belongs
to a change that was in flight when this pass ran and was not this pass's
to edit. The entry is keyed on the exact literal, so no new sentence can
shelter under it, and it fails as stale the moment the line agrees.

Pure: no database.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from test_ui_copy_no_dashes import (
    NODE,
    _const,
    _html,
    _js,
    _line_of,
    _source,
    html_visible,
    js_tokens,
)

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

#: The bracket, built rather than typed so this file does not carry the
#: hedge it forbids.
B = "(" + "s)"

#: A bracketed plural ending straight after a word, or at the start of a
#: run of template text (after `${noun}`).
HEDGE = re.compile(r"(?:^|\w)\((?:s|es|ies|y/ies|is/es)\)")

#: Exact literal text -> why it may keep its hedge.
_ALLOWED: dict[str, str] = {
    " element" + B + " were withheld from this document.": (
        "renderRedaction's fallback when the server sends no statement. The "
        "report statement code was being changed elsewhere on 2026-09-23 "
        "and was not the plural pass's to edit; drop this entry when the "
        "line agrees"),
}


# ---------------------------------------------------------------------------
# The pattern, on known text
# ---------------------------------------------------------------------------

def test_the_pattern_catches_every_spelling_and_nothing_else():
    for hedged in ("1 request" + B, "2 hypothes(is/es)", "0 entit(y/ies)",
                   "3 hypothesis(es)", "a propert(ies) list", B + " waiting"):
        assert HEDGE.search(hedged), hedged
    for plain in ("1 request", "3 requests", "(see below)", "Lists (a)",
                  "a note (s is the seconds field)", "(sent)"):
        assert not HEDGE.search(plain), plain


# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------

def test_no_string_in_app_js_hedges_a_plural():
    src = _js()
    line = _line_of(src)
    lits, _ = js_tokens(src)
    offenders = [(line(off), text) for off, text in lits
                 if HEDGE.search(text) and text not in _ALLOWED]
    assert not offenders, (
        "a count hedged with a bracketed plural; agree it with countOf(n, "
        "one, many), or agree(n, one, many) for a verb or a noun printed "
        "apart from its count: " + repr(offenders[:20]))


def test_nothing_a_reader_sees_in_index_html_hedges_a_plural():
    offenders = [(ln, where, " ".join(text.split())[:120])
                 for ln, where, text in html_visible(_html())
                 if HEDGE.search(text)]
    assert not offenders, repr(offenders[:20])


def test_the_allow_list_names_only_literals_that_still_exist():
    """An exemption outliving its literal is a hole for the next one."""
    texts = {t for _, t in js_tokens(_js())[0]}
    stale = [k for k in _ALLOWED if k not in texts]
    assert not stale, stale


def test_the_reviewed_lines_use_the_helpers():
    """The frames the review named, by function: each now builds its count
    through the helper rather than beside a hedge."""
    js = _js()
    for fn, call in (
            ("loadApprovals", "countOf(rows.length, 'request', 'requests')"),
            ("loadUnverified", "countOf(claims.length, 'claim', 'claims')"),
            ("renderSelectors", "countOf(s.observation_cnt, 'time', 'times')"),
            ("custodyVerdict", "countOf(r.forks, 'fork', 'forks')"),
            ("loadReadiness", "agree(failed, 'needs', 'need')"),
            ("renderBlockingBanner",
             "countOf(total, 'BLOCKING check', 'BLOCKING checks')"),
            ("loadTombstones", "countOf((body.tombstones || []).length,")):
        assert call in _source(js, fn), (fn, call)


# ---------------------------------------------------------------------------
# What the rewritten lines say, run under Node
# ---------------------------------------------------------------------------

_STUBS = """
function el(tag, cls, text) {
  return { tag: tag, className: cls || '',
           textContent: text === undefined || text === null ? '' : String(text),
           title: '', value: '', label: '', hidden: false, disabled: false,
           selected: false, children: [], dataset: {},
           appendChild(c) { this.children.push(c); return c; },
           setAttribute(k, v) { this[k] = v; }, addEventListener() {} };
}
const document = { createTextNode(t) {
  return { tag: '#text', textContent: String(t), children: [] }; } };
const boxes = {};
function $(id) { return boxes[id] || (boxes[id] = el('div')); }
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function text(n) {
  return (n.textContent || '') + (n.children || []).map(text).join('');
}
"""


def _run(names: list[str], body: str, tmp_path: Path, extra: str = ""):
    js = _js()
    script = tmp_path / "run.js"
    script.write_text(_STUBS + extra + "\n"
                      + "\n".join(_source(js, n) for n in names)
                      + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@needs_node
def test_the_helpers_choose_by_the_number(tmp_path):
    got = _run(["countOf", "agree"], """
console.log(JSON.stringify([
  countOf(1, 'community', 'communities'), countOf(0, 'community', 'communities'),
  countOf(6, 'community', 'communities'), agree(1, 'is', 'are'),
  agree(2, 'is', 'are'), agree('1', 'row', 'rows'),
]));
""", tmp_path)
    assert got == ["1 community", "0 communities", "6 communities", "is",
                   "are", "row"]


@needs_node
def test_the_cohesion_line_agrees_for_one_and_for_many(tmp_path):
    """The Analysis frame read "1 communities" beside a hedged count of
    components."""
    got = _run(["countOf", "agree", "renderCohesion"], """
const lines = [];
for (const c of [
    {community_count: 1, modularity: 0.4123, components: 1, component_sizes: [6]},
    {community_count: 3, modularity: 0.5, components: 2, component_sizes: [4, 2]}]) {
  renderCohesion({cohesion: c});
  lines.push(text($('an-cohesion').children[0].children[0]));
}
console.log(JSON.stringify(lines));
""", tmp_path, extra="function metricNum(v, dp) { return Number(v).toFixed(dp); }")
    assert got == [
        "1 community (Leiden, modularity 0.412) across 1 connected component "
        "of size 6.",
        "3 communities (Leiden, modularity 0.500) across 2 connected "
        "components of sizes 4, 2.",
    ]


@needs_node
def test_a_delivery_time_is_formatted_and_says_utc(tmp_path):
    """The Deliveries subtab appended the raw ISO string, the one time in
    the console that did not go through fmtTime."""
    js = _js()
    got = _run(["pad2", "fmtTime", "countOf", "deliveryRow"], """
const card = deliveryRow({kind: 'MERGE_PERFORMED', outcome: 'SENT',
  channel: 'EMAIL', recipient: 'Analyst One', address: 'a***@corp.example',
  attempts: 1, attempted_at: '2026-09-23T12:05:09.123456+00:00'});
const again = deliveryRow({kind: 'X', outcome: 'FAILED', channel: 'EMAIL',
  attempts: 3, raised_at: '2026-09-22T23:59:00Z'});
const facts = (c) => c.children[1].children.map((n) => n.textContent);
console.log(JSON.stringify([facts(card), facts(again)]));
""", tmp_path, extra=_const(js, "NO_TIME"))
    first, second = got
    assert "2026-09-23 12:05 UTC" in first, first
    assert "1 attempt" in first and not any("T12:05" in f for f in first), first
    assert "2026-09-22 23:59 UTC" in second and "3 attempts" in second, second


@needs_node
def test_a_link_endpoint_names_its_type_as_the_entity_list_does(tmp_path):
    """The Link form printed "oriel [IDENTITY]": the raw type code, where
    the entity list and the inspector chip print the type's display name."""
    got = _run(["typeName", "buildEndpointSelect"], """
const state = { nodeTypeMeta: new Map([
  ['IDENTITY', {display_name: 'Identity'}], ['WALLET', {display_name: 'Wallet'}]]) };
const pool = [{id: 'n1', label: 'oriel', node_type: 'IDENTITY'},
              {id: 'n2', label: 'bc1q', node_type: 'WALLET'}];
function endpointTerms() { return []; }
function endpointChoices() { return pool; }
function endpointPool() { return pool; }
function sortEndpoints(rows) { return rows; }
function endpointMatches() { return true; }
buildEndpointSelect('src');
const groups = $('edge-src').children.slice(1);
console.log(JSON.stringify(groups.map((g) => [g.label,
  g.children.map((o) => o.textContent)])));
""", tmp_path)
    assert got == [["Identity (IDENTITY)", ["oriel (Identity)"]],
                   ["Wallet (WALLET)", ["bc1q (Wallet)"]]], got


@needs_node
def test_the_readiness_summary_agrees_its_verb(tmp_path):
    got = _run(["countOf", "agree", "loadReadiness"], """
let reply;
async function api() { return reply; }
function renderBlockingBanner() {}
function readinessRow() { return el('div'); }
function refusalText(err, fallback) { return fallback; }
(async () => {
  const out = [];
  for (const checks of [[{ok: false}, {ok: true}, {ok: true}],
                        [{ok: false}, {ok: false}, {ok: true}]]) {
    reply = {ready: false, checks: checks};
    await loadReadiness();
    out.push($('rdy-summary').textContent);
  }
  console.log(JSON.stringify(out));
})();
""", tmp_path)
    assert got == ["1 of 3 checks needs attention.",
                   "2 of 3 checks need attention."], got


_ACH_BODY = """
function fact(k, v, cls) { return el('span', 'fact ' + (cls || ''), k + ' ' + v); }
function withSafeLabel(r) { return r; }
const hyp = (id) => ({id: id, statement: id, inconsistency: 0, support: 0,
                      assessed: 1, unassessed: 0});
function nextLine(evidence, cells, hypotheses) {
  renderAchRanking({hypotheses: hypotheses, evidence: evidence, cells: cells,
                    refute_first: 'a1', least_inconsistent: null});
  const kids = $('ach-ranking').children;
  return text(kids[kids.length - 1]);
}
"""


@needs_node
def test_the_next_test_line_reads_as_english_for_both_kinds_of_row(tmp_path):
    """An unfinished row's diagnosticity is unknown, so it is not "the most
    diagnostic item"; the columns it lacks are listed as a sentence lists
    them; and a blank cell is not "a neutral" but a neutral one."""
    got = _run(["achNextTest", "renderAchRanking"], """
const four = ['h1', 'h2', 'h3', 'h4'].map(hyp);
console.log(JSON.stringify([
  nextLine([{assertion_id: 'a1', label: 'hal_quarry', is_incomplete: true}],
           [{assertion_id: 'a1', hypothesis_id: 'h1'}], four),
  nextLine([{assertion_id: 'a1', label: 'same builder', is_incomplete: false}],
           [{assertion_id: 'a1', hypothesis_id: 'h1'},
            {assertion_id: 'a1', hypothesis_id: 'h2'}], four),
  nextLine([{assertion_id: 'a1', label: 'one gap', is_incomplete: false}],
           [{assertion_id: 'a1', hypothesis_id: 'h1'},
            {assertion_id: 'a1', hypothesis_id: 'h2'},
            {assertion_id: 'a1', hypothesis_id: 'h3'}], four),
]));
""", tmp_path, extra=_ACH_BODY)
    unfinished, partial, single = got
    assert unfinished == (
        "next test Score hal_quarry against H2, H3 and H4. Its row is "
        "unfinished, so its diagnosticity is unknown rather than zero, and "
        "finishing the row is the cheapest work available here."), unfinished
    assert partial == (
        "next test Score same builder against H3 and H4. It is the most "
        "diagnostic item with a blank cell, and a blank cell is a gap, not a "
        "neutral one."), partial
    assert "against H4. It is the most diagnostic" in single, single
