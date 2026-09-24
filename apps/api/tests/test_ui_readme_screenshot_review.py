"""Console defects the README screenshots exposed (2026-09-23).

Round 1 of the README screenshot work put sixteen panes in front of eight
adversarial critics, and several of the problems they found were in the
product rather than in the data or the framing: copy that contradicted the
drawing beside it, a preview that broke the one value it exists to show,
a form row that wrapped every channel onto three lines, notes to the
developer shown to the analyst, and a matrix whose own marker could never
render. Each is held here so the next capture cannot show it again.

Pure, like `test_ui_invariants.py` beside it: these read the shipped static
assets and the service source, with no database and no browser. The checks
marked `needs_node` EXECUTE the shipped functions under Node with a small
DOM stub, because "the marker lands on the right row" is a claim about
behaviour; they skip where Node is not installed.
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

_DASHES = re.compile("[\u2013\u2014]")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _css() -> str:
    """app.css without its comments, so a rule is matched and not the
    comment explaining why it exists."""
    return re.sub(r"/\*.*?\*/", "",
                  (STATIC / "app.css").read_text(encoding="utf-8"), flags=re.S)


def _code(text: str) -> str:
    """JavaScript with its comments removed."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _visible(html: str) -> str:
    """index.html as a reader meets it: no comments."""
    return re.sub(r"<!--.*?-->", "", html, flags=re.S)


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first column-0 `}`."""
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _rule(selector: str) -> str:
    """The declarations of every CSS rule whose selector list contains
    `selector` exactly, in file order."""
    found = [m.group(2) for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", _css())
             if selector in [s.strip() for s in m.group(1).split(",")]]
    assert found, f"no CSS rule for {selector}"
    return "\n".join(found)


def _deceptive() -> str:
    js = _js()
    start = js.index("const _DECEPTIVE = new RegExp(")
    return js[start:js.index("]', 'g');", start) + len("]', 'g');")]


_STUBS = """
function el(tag, cls, text) {
  return { tag: tag, className: cls || '',
           textContent: text === undefined || text === null ? '' : String(text),
           title: '', children: [], attrs: {},
           setAttribute(k, v) { this.attrs[k] = v; },
           appendChild(c) { this.children.push(c); return c; } };
}
const document = { createTextNode(t) { return { tag: '#text', textContent: t }; } };
function fmtTime(x) { return 'T(' + x + ')'; }
function shortId(id) { return id ? id.slice(0, 8) : '-'; }
"""


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text(_STUBS + "\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# Deception: the Received chain's help said "above" over a drawing that
# puts the outside hops below
# ---------------------------------------------------------------------------

def test_the_received_chain_note_points_where_the_drawing_puts_the_claims():
    """The server lists hops `ORDER BY seq` and the console draws them in
    that order, hop 0 (the recipient's own MTA) at the top; a hop is
    attacker-writable when its seq is ABOVE the boundary's, which on
    screen is BELOW the boundary row. The note and the chip said "above",
    so the README hero explained its headline claim backwards."""
    service = (SRC / "deception.py").read_text(encoding="utf-8")
    assert "WHERE message_id = %s ORDER BY seq" in service
    assert '"is_attacker_writable": h[0] > boundary' in service

    card = _code(_js()[_js().index("chain.appendChild(el('h3', 'h-xs', 'Received chain'))"):])
    card = card[:card.index("body.appendChild(chain);")]
    assert "for (const h of hops)" in card, "the hops are no longer drawn in order"
    assert "Read this from the top" in card
    assert "below the trust boundary" in card
    assert "further from the recipient" in card
    assert "above the boundary" not in card
    assert "everything above it" not in card.lower()


def test_no_deception_string_says_the_claims_sit_above_the_boundary():
    js = _js()
    start = js.index("/* --- deception: phishing captures, BEC email")
    region = _code(js[start:js.index("/* --- wiring ---", start)])
    for wrong in ("Everything above it in the chain", "everything above it is a claim",
                  "Everything above the boundary"):
        assert wrong not in region, wrong


# ---------------------------------------------------------------------------
# Comms: the preview broke a 64-hex key in two, and a note began a sentence
# in lower case
# ---------------------------------------------------------------------------

def test_the_normalise_preview_puts_its_label_above_the_value():
    """Side by side, the label took about 140px of the 620px card and a
    64-hex Tox key (about 460px at 12px mono) wrapped mid-identifier."""
    row = _rule(".preview-row")
    assert "flex-direction: column" in row
    html = _html()
    assert re.search(r'<div class="preview-row">\s*<span class="label">Will be '
                     r'indexed as</span>\s*<code id="comms-preview-durable"', html)


@needs_node
def test_a_server_note_is_shown_as_a_sentence(tmp_path):
    got = _run([_fn("asSentence")], """
console.log(JSON.stringify([
  asSentence('a Telegram @username is NOT durable: usernames are recycled.'),
  asSentence('normalised to the 64-hex public key; the nospam is NOT part of the identity'),
  asSentence('not a Tox ID: expected 76 hex (public key + nospam + checksum)'),
  asSentence(''), asSentence(null), asSentence('  already fine.  '),
]));
""", tmp_path)
    assert got[0].startswith("A Telegram @username")
    assert got[1].startswith("Normalised") and got[1].endswith("identity.")
    assert got[2].endswith("checksum).")
    assert got[3:5] == ["", ""]
    assert got[5] == "Already fine."


def test_every_place_the_pane_puts_a_note_after_a_full_stop_uses_asSentence():
    code = _code(_js())
    assert re.search(r"'No durable value, so nothing can correlate\. '\s*"
                     r"\+ asSentence\(body\.note\)", code)
    assert "'Recorded. ' + asSentence(" in code
    assert "$('comms-preview-note').textContent = asSentence(body.note)" in code
    assert "'No durable value, so nothing can correlate. ' + (body.note" not in code
    # "0 binding(s) in this case" was in the capture; the count is known.
    correlate = _code(_fn("initCommsCorrelate"))
    assert "binding(s)" not in correlate
    assert "(n === 1 ? ' binding' : ' bindings')" in correlate
    # The shot recipe waits on "Correlating on <key> " with the space.
    assert "'Correlating on ' + body.durable_value + ' finds '" in correlate


def test_the_telegram_notes_read_as_sentences_and_carry_no_review_codes():
    from noctornal_api.comms import normalise
    username = normalise("TELEGRAM", "@mer_kite")
    assert username.durable is None
    assert username.note.startswith("A Telegram @username is NOT durable")
    assert " -- " not in username.note
    channel = normalise("TELEGRAM", "-1001234567890")
    assert channel.durable
    assert not re.search(r"\(CR\d+\)|\d{4}-\d{2}-\d{2}", channel.note), channel.note
    assert channel.note[0].isupper()


# ---------------------------------------------------------------------------
# Notifications: every channel's priority select stretched the row
# ---------------------------------------------------------------------------

def test_a_delivery_preference_select_is_sized_to_its_options():
    """The base `input, select, textarea { width: 100% }` made each priority
    select about 930px wide, so SMTP, WEBHOOK and JIRA each wrapped onto
    three lines."""
    assert "width: 100%" in _rule("select")
    assert "width: auto" in _rule(".pref-row select")
    prefs = _fn("loadInboxPreferences")
    # Named by a visible <label> since ux08-triage:prefs-unlabelled-and-
    # opaque (2026-09-23), which is also the name a screen reader reads.
    assert "prefField('Minimum priority', priority)" in prefs
    assert "prefField('Quiet from', from)" in prefs


def test_the_inbox_help_names_every_half_of_the_read_time_filter():
    """`readable_predicate` checks clearance, compartments and a live case
    assignment; the line named clearance alone."""
    predicate = (SRC / "notifications.py").read_text(encoding="utf-8")
    assert "iam.case_assignment" in predicate and "compartments <@" in predicate
    text = " ".join(_visible(_html()).split())
    assert ("filtered by your CURRENT clearance, compartments and case "
            "assignments") in text
    assert "a case you were taken off" in text


# ---------------------------------------------------------------------------
# Stale and developer-facing copy
# ---------------------------------------------------------------------------

def test_the_inspector_does_not_call_brokerage_unbuilt():
    """"is Phase 3 and is not computed here" sat beside a computed
    key-player card; Phase 3 shipped."""
    text = " ".join(_visible(_html()).split())
    assert "is Phase 3" not in text
    assert "not computed here" not in text
    # An instruction since the ux19-copy stale-phase3-claim fix
    # (2026-09-23): it says where to run brokerage, not only where it is.
    assert ("Brokerage (betweenness, Burt's constraint, key-player "
            "fragmentation) is global, so it is not on this panel: run it on "
            "the Analysis pane") in text
    assert '<span class="rail-cap">Analysis</span>' in _html()


def test_no_design_document_is_cited_to_the_analyst():
    """"docs/09 asks for this to be keyboard driven" was on screen in
    Triage. The documents are the developer's; the analyst never sees
    them, so a citation is noise at best."""
    visible = _visible(_html())
    assert not re.findall(r"docs/\d\d", visible), re.findall(r".{40}docs/\d\d.{20}", visible)
    code = _code(_js())
    strings = re.findall(r"'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`", code)
    cited = [s for s in strings if re.search(r"docs/\d\d", s)]
    assert not cited, cited
    # True to onTriageKey, which acts only inside the list since
    # ux18-a11y:triage-letter-keys-global and only on a card or the list,
    # never a button, a field or a chord, since ux08-triage:triage-keys-
    # fire-on-browser-chords (2026-09-23).
    assert "list.contains(target)" in _fn("onTriageKey")
    assert "triageKeyTarget(target)" in _fn("onTriageKey")
    assert ("The keys work while the list below has the focus"
            ) in " ".join(visible.split())


# ---------------------------------------------------------------------------
# ACH: the "refute first" marker could never render, and the ranking drew
# its losers in the winner's colour
# ---------------------------------------------------------------------------

def test_refute_first_is_compared_with_evidence_not_with_hypotheses():
    """ach.py: `refute_first` is the ASSERTION id of the most diagnostic
    item with a blank cell. The ranking compared it with each HYPOTHESIS
    id, so it never matched."""
    service = (SRC / "ach.py").read_text(encoding="utf-8")
    assert "max(gaps, key=lambda d: d.score).assertion_id" in service
    ranking = _code(_fn("renderAchRanking"))
    assert "String(h.id) === body.refute_first" not in ranking
    assert "achNextTest(body)" in ranking
    matrix = _code(_fn("renderAchMatrix"))
    assert "String(e.assertion_id) === String(body.refute_first)" in matrix


def _ach_consts() -> str:
    """ACH_STATUS and ACH_STATUS_CHIP, which the ranking cards read."""
    js = _js()
    found = [m.group(0) for name in ("ACH_STATUS", "ACH_STATUS_CHIP")
             for m in [re.search(r"(?ms)^const " + name + r" = [\[{].*?^[\]}];", js)]
             if m]
    assert len(found) == 2, "ACH_STATUS or ACH_STATUS_CHIP is gone"
    return "\n".join(found)


#: The helpers the ACH renderers call since the ux11-ach pass (2026-09-23):
#: the stable column key and order, the labelled score, the card, and the
#: row's subject, claim and evidence cell.
_ACH_HELPERS = ("achKey", "achColumns", "achNum", "achAnd", "achCard",
                "achSubject", "achClaim", "achEvidenceCell")


def _ach_sources() -> list[str]:
    return [_deceptive(), _fn("visibleText"), _fn("withSafeLabel"),
            _ach_consts(), *(_fn(n) for n in _ACH_HELPERS)]


@needs_node
def test_the_next_test_names_the_row_and_the_hypotheses_it_lacks(tmp_path):
    """The blank columns are named by their stable keys, in key order,
    whatever order the ranking lists the hypotheses in."""
    got = _run([*_ach_sources(), _fn("achNextTest")], """
const body = {
  hypotheses: [{id: 'h2', number: 2}, {id: 'h3', number: 3}, {id: 'h1', number: 1}],
  evidence: [{assertion_id: 'a1', label: 'same builder'},
             {assertion_id: 'a2', label: 'hal_\\u202Equarry'}],
  cells: [{assertion_id: 'a1', hypothesis_id: 'h1'},
          {assertion_id: 'a1', hypothesis_id: 'h2'},
          {assertion_id: 'a1', hypothesis_id: 'h3'},
          {assertion_id: 'a2', hypothesis_id: 'h1'},
          {assertion_id: 'a2', hypothesis_id: 'h2'}],
  refute_first: 'a2',
};
console.log(JSON.stringify([
  achNextTest(body),
  achNextTest(Object.assign({}, body, {refute_first: null})),
  achNextTest(Object.assign({}, body, {refute_first: 'h2'})),
]));
""", tmp_path)
    found, none, hypothesis_id = got
    assert found["missing"] == ["H3"]
    assert found["first"]["id"] == "h3", "Score it now opens the first blank"
    assert found["label"] == "hal_‹U+202E›quarry", "a forum label is made safe"
    assert none is None
    assert hypothesis_id is None, "a hypothesis id names no evidence row"


_MATRIX_STUBS = """
const boxes = {};
function $(id) { return boxes[id] || (boxes[id] = el('div')); }
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function fact(k, v, cls) { return el('span', 'fact ' + (cls || ''), k + ' ' + v); }
function renderAchHypothesisPicker() {}
const STANCE_CLASS = {'-2': 'st-cc', '-1': 'st-c', '0': 'st-n', '1': 'st-s', '2': 'st-ss'};
function stanceText(s) { return String(s); }
const _el = el;
el = function (tag, cls, text) {
  const n = _el(tag, cls, text);
  n.dataset = {}; n.addEventListener = () => {};
  return n;
};
const body = {
  // Numbered in writing order, listed in rank order: the imitator was
  // written first and ranks last (ux11-ach:h-numbers-unstable, 2026-09-23).
  hypotheses: [{id: 'h1', number: 2, statement: 'separate operators', inconsistency: 0,
                support: 2.2, assessed: 3, unassessed: 0},
               {id: 'h2', number: 3, statement: 'same operator', inconsistency: 1.4,
                support: 2.2, assessed: 3, unassessed: 0},
               {id: 'h3', number: 1, statement: 'imitator', inconsistency: 0.7,
                support: 1.4, assessed: 2, unassessed: 1}],
  evidence: [{assertion_id: 'a1', label: 'same builder', diagnosticity: 3,
              is_diagnostic: true, is_incomplete: false, assessed_against: 3},
             {assertion_id: 'a2', label: 'hal_quarry', diagnosticity: 0,
              is_diagnostic: false, is_incomplete: true, assessed_against: 2}],
  cells: [{assertion_id: 'a1', hypothesis_id: 'h1', stance: 1},
          {assertion_id: 'a1', hypothesis_id: 'h2', stance: 2},
          {assertion_id: 'a1', hypothesis_id: 'h3', stance: -1},
          {assertion_id: 'a2', hypothesis_id: 'h1', stance: 1},
          {assertion_id: 'a2', hypothesis_id: 'h2', stance: 1}],
  least_inconsistent: 'h1', refute_first: 'a2', statuses: {}, stance_scale: {},
};
"""


@needs_node
def test_the_next_test_marker_renders_on_its_evidence_row(tmp_path):
    """Executes the shipped ranking and matrix renderers: the marker the
    old comparison could never draw now lands on the row `refute_first`
    names, the dash on that row says why it is unknown, and the ranking
    names the blank column."""
    got = _run([*_ach_sources(), _fn("achNextTest"), _fn("achUnknownWhy"),
                _fn("renderAchRanking"), _fn("renderAchMatrix"),
                _MATRIX_STUBS], """
renderAchRanking(body);
renderAchMatrix(body);
const text = (n) => (n.textContent || '') + (n.children || []).map(text).join('');
const head = $('ach-matrix').children[0].children[0].children[0].children;
const rows = $('ach-matrix').children[0].children[1].children;
const diag = (r) => r.children[r.children.length - 1];
console.log(JSON.stringify({
  ranking: $('ach-ranking').children.map(text),
  header: head.map(text),
  rowClasses: rows.map((r) => r.className),
  gaps: rows.map((r) => r.children.filter((c) => /st-gap/.test(c.className)).length),
  diagText: rows.map((r) => text(diag(r))),
  diagTitle: rows.map((r) => diag(r).title),
}));
""", tmp_path)
    # The card carries its column's key, and the score says what it is.
    assert got["ranking"][0].startswith("against 0.00H2separate operators")
    assert got["ranking"][1].startswith("against 1.40H3same operator")
    assert "next test" in got["ranking"][-1]
    assert "Score hal_quarry against H1" in got["ranking"][-1]
    assert got["ranking"][-1].endswith("Score it now")
    # Columns in writing order, each with its statement, not rank order.
    assert got["header"][1:4] == ["H1imitator", "H2separate operators",
                                  "H3same operator"]
    assert got["rowClasses"] == ["", "row-incomplete"]
    assert got["gaps"] == [0, 1], "the unfinished row's blank is outlined"
    assert "next test" not in got["diagText"][0]
    # The unknown row says so in the warning's own word, not with a glyph
    # a numeric column reads as "no value".
    assert got["diagText"][1].startswith("unfinished") and "next test" in got["diagText"][1]
    assert not _DASHES.search(got["diagText"][1])
    assert "2 of 3 hypotheses" in got["diagTitle"][1]
    assert "Still to score: H1." in got["diagTitle"][1], (
        "the row names the hypothesis it is owed")
    assert not any("refute this first" in r for r in got["ranking"])


def test_the_ranking_ties_each_card_to_its_matrix_column_and_colours_against():
    card = _code(_fn("achCard"))
    assert "achKey(h)" in card, "a card must carry its matrix column's key"
    assert "return 'H' + h.number;" in _code(_fn("achKey")), (
        "the key is the stable number, never the rank")
    assert "' against'" in card and "' hot'" not in card
    assert "'against ' + achNum(h.inconsistency)" in card, "the score is labelled"
    assert "var(--danger)" in _rule(".score.against")
    assert "var(--accent)" in _rule(".score.hot"), (
        "`.score.hot` is shared with triage, lifecycle and deception and "
        "keeps its meaning there")


@needs_node
def test_an_unknown_row_says_which_kind_of_unknown(tmp_path):
    got = _run([_fn("achUnknownWhy")], """
console.log(JSON.stringify([
  achUnknownWhy({assessed_against: 0}, 3),
  achUnknownWhy({assessed_against: 1}, 3),
  achUnknownWhy({assessed_against: 2}, 3),
]));
""", tmp_path)
    assert "no hypotheses" in got[0]
    assert "only one hypothesis" in got[1]
    assert "2 of 3 hypotheses" in got[2] and "says the same thing" in got[2]


def test_the_matrix_help_matches_the_service_rule():
    text = " ".join(_visible(_html()).split())
    assert "Evidence that says the same thing about <em>every</em> hypothesis" in text
    assert "unfinished, not undiagnostic" in text
    # The help names what the cell shows, and the cell shows it.
    assert "reads <em>unfinished</em> until it is scored against the rest" in text
    assert "e.is_incomplete ? 'unfinished'" in _code(_fn("renderAchMatrix"))
    from noctornal_api.ach import as_response, score
    method = as_response(score([], []))["method"]
    assert "says the same thing about every hypothesis" in method
    assert " -- " not in method


# ---------------------------------------------------------------------------
# Report: the redaction statement's Markdown bold, and the pane's rhythm
# ---------------------------------------------------------------------------

@needs_node
def test_the_redaction_statement_renders_its_bold_rather_than_its_asterisks(tmp_path):
    """reports.Redaction.statement() bolds "Every figure below is computed
    over the redacted graph" with `**`, and the card printed it through
    textContent, so the asterisks showed whenever anything was withheld."""
    got = _run([_fn("withStrongRuns")], """
const show = (n) => n.children.map((c) => [c.tag, c.textContent]);
console.log(JSON.stringify([
  show(withStrongRuns(el('p'), 'Withheld. **Every figure below is computed over the redacted graph** and is a lower bound.')),
  show(withStrongRuns(el('p'), 'No bold at all.')),
  show(withStrongRuns(el('p'), 'An unpaired ** marker <b>stays</b> as written.')),
]));
""", tmp_path)
    bold, plain, unpaired = got
    assert bold == [["#text", "Withheld. "],
                    ["strong", "Every figure below is computed over the redacted graph"],
                    ["#text", " and is a lower bound."]]
    assert plain == [["#text", "No bold at all."]]
    assert unpaired == [["#text", "An unpaired "],
                        ["#text", "** marker <b>stays</b> as written."]]
    assert "withStrongRuns(el('p', anything ? 'why prose' : 'help')" in _fn("renderRedaction")
    # `.card .why` is a flex row (label + value lines); flexed, this
    # sentence split into three items and its bold run left the line.
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert ".card .why.prose { display: block; }" in css


def test_the_statement_the_card_renders_does_carry_markdown_bold():
    """The other half: if the service stops writing `**`, this helper is
    dead weight and the test says so."""
    from noctornal_api.reports import Redaction
    statement = Redaction(built_at_tlp="CLEAR", ceiling_tlp="CLEAR",
                          case_tlp="CLEAR", nodes_withheld=0, edges_withheld=0,
                          evidence_withheld=1).statement()
    assert "**Every figure below is computed over the redacted graph**" in statement


def test_the_report_and_retention_sections_are_spaced():
    assert "margin-top" in _rule("#rep-redaction > .row-card")
    assert "margin-top" in _rule("#rep-body > h2.h-sm")
    assert "margin-top" in _rule("#gov-retention > h2.h-sm:not(:first-child)")


# ---------------------------------------------------------------------------
# Analysis: the trend canvas was never sized after the first Run
# ---------------------------------------------------------------------------

def test_showing_the_results_sizes_the_trend_canvas():
    """`resizeHistory` ran only on tab entry, and on entry to a case with no
    run the results are hidden, so the canvas kept its 300x150 bitmap and
    the chart was a blurred strip."""
    render = _code(_fn("renderAnalytics"))
    shown = render.index("show($('an-results'), true)")
    assert "resizeHistory();" in render[shown:], (
        "the canvas must be sized after the results are shown")
    assert "if (!w || !h) return;" in _fn("resizeHistory")


# ---------------------------------------------------------------------------
# Feeds, Evidence, Entities, Lifecycle, and the styled select
# ---------------------------------------------------------------------------

def test_the_dead_letter_help_is_true_of_a_fragment_that_never_parsed():
    """"keys, types and lengths, never values" stood above three rows that
    had never parsed and so showed a bare [redacted] (redact_text keeps no
    type and no length)."""
    ingest = (SRC / "ingest.py").read_text(encoding="utf-8")
    assert 'return f"[redacted {type(value).__name__}:{len(text)}]"' in ingest
    text = " ".join(_visible(_html()).split())
    assert "keys, types and lengths, never values" not in text
    assert "A fragment that parsed keeps each value's type and length" in text
    assert "one that would not parse is masked line by line" in text


def test_the_file_picker_button_is_themed():
    rule = _rule('input[type="file"]::file-selector-button')
    for token in ("var(--wash-2)", "var(--field-edge)", "var(--text-secondary)"):
        assert token in rule, token


@needs_node
def test_a_custody_row_names_the_person(tmp_path):
    got = _run([_deceptive(), _fn("visibleText"), _fn("custodyHashChip"),
                _fn("renderCustodyRow")], """
const rows = [
  {action: 'VIEWED', occurred_at: 'x', actor_id: 'fcfd6f27-0000', hash_verified: null,
   actor_name: 'Demo Analyst'},
  {action: 'VIEWED', occurred_at: 'x', actor_id: 'fcfd6f27-0000', hash_verified: null,
   actor_name: null},
];
console.log(JSON.stringify(rows.map((c) => {
  const r = renderCustodyRow(c);
  return [r.children[2].textContent, r.children[2].title];
})));
""", tmp_path)
    named, unresolved = got
    assert named == ["by Demo Analyst", "Account fcfd6f27-0000"]
    assert unresolved == ["account fcfd6f27", "Account fcfd6f27-0000"]


def test_the_custody_route_carries_the_actor_name():
    from noctornal_api.http.routers.evidence import CustodyOut
    assert "actor_name" in CustodyOut.model_fields
    service = (SRC / "evidence.py").read_text(encoding="utf-8")
    assert "LEFT JOIN iam.app_user u ON u.id = c.actor_id" in service


def test_a_styled_select_draws_its_chevron_even_when_focused():
    """`select.select` set `appearance: none` and drew nothing in its place,
    so Triage's Classification and Queue read as text fields. The base
    `select:focus` rule resets the `background` shorthand, so the chevron
    rule has to cover :focus too."""
    for selector in ("select.select", "select.select:focus"):
        rule = _rule(selector)
        assert "linear-gradient" in rule and "no-repeat" in rule, selector
    assert "url(" not in _rule("select.select")
    # A listbox has nothing to drop down. Admin's roles picker was the
    # console's one listbox until it became checkboxes (ux16-admin:
    # create-roles-multiselect, 2026-09-23); the rule stays, so the next
    # listbox does not grow a chevron.
    assert "background-image: none" in _rule("select.select[multiple]")


def test_a_missing_first_seen_is_drawn_as_missing():
    rows = _code(_fn("renderEntities"))
    assert "n.first_seen ? 'num' : 'num absent'" in rows
    assert "var(--text-tertiary)" in _rule(".table td.absent")


@needs_node
def test_a_retention_period_says_day_or_days(tmp_path):
    got = _run([_fn("dayCount"), _fn("countOf")], """
console.log(JSON.stringify([dayCount(1), dayCount(730), dayCount('90')]));
""", tmp_path)
    assert got == ["1 day", "730 days", "90 days"]
    assert "day(s)" not in _code(_fn("syncRuleForm"))
    assert "day(s)" not in _code(_fn("wireRetentionConfirm"))


@needs_node
def test_a_count_on_the_ach_and_report_panes_agrees_with_its_noun(tmp_path):
    """"3 hypotheses · 3 item(s) of evidence" headed the ACH shot, and the
    Report pane's stand-in for withheld assumptions hedged the same way."""
    got = _run([_fn("countOf")], """
console.log(JSON.stringify([
  countOf(1, 'item of evidence', 'items of evidence'),
  countOf(3, 'item of evidence', 'items of evidence'),
  countOf(0, 'recorded assumption', 'recorded assumptions'),
]));
""", tmp_path)
    assert got == ["1 item of evidence", "3 items of evidence", "0 recorded assumptions"]
    ach = _code(_fn("loadAch"))
    assert "item(s)" not in ach
    assert "countOf(body.evidence.length, 'item of evidence', 'items of evidence')" in ach
    report = _code(_js())
    assert "' recorded assumption(s) withheld" not in report
    assert "countOf(assumptionsWithheld," in report


# ---------------------------------------------------------------------------
# A refusal's detail and the console's sentence after it
# ---------------------------------------------------------------------------

_API_ERROR = """
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail; }
}
"""


@needs_node
def test_a_refusal_detail_is_closed_before_the_sentence_after_it(tmp_path):
    """The Break-glass subtab printed "missing global permission
    break_glass.review The review belongs to the security officer", the
    server's clause and the console's sentence run together as one."""
    # With no role table read from the server (`permissionRoles` null) a
    # refusal reads as it always did; the role-named form is held by
    # test_a_refusal_names_the_roles_and_who_can_give_one in
    # test_search_palette_copy_ui.py, and every context against the real
    # grant table by test_every_refusal_reads_as_a_sentence_against_the_
    # real_grant_table in test_search_columns_pg.py.
    got = _run([_API_ERROR, _fn("refusalText"), _fn("closeClause"),
                _fn("permissionRefusal"), _fn("roleWords"), _fn("rolesFor"),
                _fn("listWords"), "let permissionRoles = null;"], """
const e = (d) => new ApiError(403, 'Forbidden', d);
console.log(JSON.stringify([
  refusalText(e('missing global permission break_glass.review'),
              'The review belongs to the security officer.'),
  refusalText(e('missing global permission break_glass.review'), ''),
  refusalText(e('case.read required on this case'), 'Ask the owner.'),
  refusalText(e('Account inactive.'), 'Ask an administrator.'),
  refusalText(new Error('x'), 'Only the context.'),
]));
""", tmp_path)
    assert got[0] == ("Missing global permission break_glass.review. "
                      "The review belongs to the security officer.")
    assert got[1] == "missing global permission break_glass.review", (
        "a detail with nothing after it is the server's words as sent")
    assert got[2] == "case.read required on this case. Ask the owner.", (
        "an identifier is never capitalised into something else")
    assert got[3] == "Account inactive. Ask an administrator."
    assert got[4] == "Only the context."


# ---------------------------------------------------------------------------
# Triage: a chord is never a verdict
# ---------------------------------------------------------------------------

@needs_node
def test_a_triage_key_with_a_modifier_is_left_to_the_browser(tmp_path):
    """Ctrl+A (select all) accepted the highlighted proposal with no
    prompt; Ctrl+R and Ctrl+D opened the reject and defer prompts."""
    got = _run([_fn("triageKeyTarget"), _fn("onTriageKey")], """
const calls = [];
const state = { tab: 'triage', triage: [{id: 1}, {id: 2}], triageIndex: 0 };
function acceptProposal() { calls.push('accept'); }
function rejectProposal() { calls.push('reject'); }
function deferProposal() { calls.push('defer'); }
function renderTriage() {}
// The list holds the focus: since 2026-09-23 the letters act only inside
// it, and A asks first (ux18-a11y:triage-letter-keys-global).
function $() { return { children: [], hidden: true, contains: () => true }; }
document.body = { tagName: 'BODY' };
function anyDialogOpen() { return false; }
function triageLettersOn() { return true; }
function triageAcceptQuestion() { return 'Accept?'; }
const window = { confirm: () => true };
const press = (key, mods) => {
  let prevented = false;
  onTriageKey(Object.assign({ key: key, target: document.body,
    preventDefault() { prevented = true; } }, mods || {}));
  return prevented;
};
const chords = [press('a', {ctrlKey: true}), press('r', {ctrlKey: true}),
                press('d', {metaKey: true}), press('j', {altKey: true})];
const afterChords = { calls: calls.slice(), index: state.triageIndex };
const plain = [press('j'), press('a')];
console.log(JSON.stringify({ chords, afterChords, plain, calls,
                             index: state.triageIndex }));
""", tmp_path)
    assert got["chords"] == [False, False, False, False], "a chord was taken"
    assert got["afterChords"] == {"calls": [], "index": 0}
    assert got["plain"] == [True, True]
    assert got["calls"] == ["accept"] and got["index"] == 1


# ---------------------------------------------------------------------------
# Search: a hit found through an attribute says which one
# ---------------------------------------------------------------------------

@needs_node
def test_a_hit_found_by_an_attribute_says_which_attribute(tmp_path):
    """"meridian" found mer_ash, mer_kite and mer_ledger through
    crew=meridian and the line under each was empty, so the hits read as
    a match on the "mer" of their names. The server half is
    test_a_hit_found_only_by_an_attribute_names_the_attribute in
    test_search_selectors_pg.py."""
    got = _run([_deceptive(), _fn("visibleText"), _fn("viaLine")], """
const sel = {selector_type: 'JABBER', value: 'ledger@meridian.example',
             exact: false, more: 0, merged_from: null};
console.log(JSON.stringify([
  viaLine({label: 'mer_kite', via: null, attribute: 'crew'}, 'meridian'),
  viaLine({label: 'mer_kite', via: null, attribute: 'cr\\u202Eew'}, 'meridian'),
  viaLine({label: 'mer_ledger', via: sel, attribute: null}, 'meridian'),
  viaLine({label: 'mer_ash', via: null, attribute: null}, 'meridian'),
  viaLine({label: 'mer_ash', via: null, attribute: 'crew', merged_name: 'old_mer'},
          'meridian'),
]));
""", tmp_path)
    assert got[0] == "via attribute crew"
    assert got[1] == "via attribute cr‹U+202E›ew", "an attribute key is de-fanged"
    assert got[2].startswith("via selector JABBER")
    assert got[3] == ""
    assert got[4] == "via the name of merged record old_mer"


# ---------------------------------------------------------------------------
# No em or en dash in anything this pass put in front of a reader
# ---------------------------------------------------------------------------

_WRITTEN = ("asSentence", "achNextTest", "achUnknownWhy", "withStrongRuns",
            "dayCount", "syncRuleForm", "countOf", "closeClause", "viaLine",
            "onTriageKey")


def test_no_dash_reaches_the_reader_from_the_rewritten_functions():
    offenders = [(name, s) for name in _WRITTEN
                 for s in re.findall(r"'(?:[^'\\\n]|\\.)*'", _fn(name))
                 if _DASHES.search(s)]
    assert not offenders, offenders


def test_no_dash_in_the_rewritten_help_lines():
    text = " ".join(_visible(_html()).split())
    for anchor in ("Brokerage (betweenness", "The keys work while",
                   "Fragments are <strong>structurally redacted</strong>",
                   "filtered by your CURRENT clearance",
                   "A cell is how one piece of evidence"):
        start = text.index(anchor)
        sentence = text[start:text.index("</p>", start)]
        assert not _DASHES.search(sentence) and "&mdash;" not in sentence, anchor
