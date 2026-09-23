"""The inspector and the custody log, as the console renders them (2026-09-22).

Four findings of the 2026-09-22 review live in the console rather than the
API, and each was a sentence or a chip telling the analyst something false:

- ux07 custody-failed-hash-shown-as-not-checked: a failed hash check
  rendered as a grey "hash not checked", indistinguishable from a row that
  attests no check at all.
- ux05 retract-confirmation-wrong: the Retract prompt counted the RENDERED
  list (dead rows included) and promised an as-of recovery that the
  projection does not provide.
- ux05 parallel-ties-unreachable / ux18 edges-mouse-only: a tie could be
  opened only by a mouse click that found the first link within 6px.
- ux05 assertion-drops-claim-and-source: the card never said what was
  claimed, from what, or by whom.

Pure: no database, no browser. The static checks run everywhere. The
checks marked `needs_node` EXECUTE the shipped functions under Node with a
three-line DOM stub, because "the false branch renders red" is a claim
about behaviour, and reading the source for a class name would pass on a
function that never reaches it. CI's Python job has no Node, so they skip
there and run on a developer machine.
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
APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"

_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _code() -> str:
    """app.js without its comments. The comments that explain these fixes
    quote the old strings on purpose; the checks are about what RUNS."""
    js = re.sub(r"/\*.*?\*/", "", _js(), flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", js)


def _function(name: str) -> str:
    """A top-level function's source, closed on the first `}` at column 0."""
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start) + 2]


def _deceptive() -> str:
    js = _js()
    start = js.index("const _DECEPTIVE = new RegExp(")
    return js[start:js.index("]', 'g');", start) + len("]', 'g');")]


#: Just enough DOM for the render helpers: `el` as the console defines it,
#: minus the document.
_STUBS = """
function el(tag, cls, text) {
  return { tag: tag, className: cls || '',
           textContent: text === undefined || text === null ? '' : String(text),
           title: '', children: [],
           appendChild(c) { this.children.push(c); return c; } };
}
function fmtTime(x) { return 'T(' + x + ')'; }
function shortId(id) { return id ? id.slice(0, 8) : '-'; }
"""


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text(_STUBS + "\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True,
                         text=True, encoding="utf-8",
                         timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# Custody: three states, and a failed check is the loudest thing in the row
# ---------------------------------------------------------------------------

@needs_node
def test_a_failed_hash_check_renders_as_a_red_mismatch(tmp_path):
    """The test the finding asked for: render a hash_verified=false row."""
    got = _run([_function("custodyHashChip"), _function("renderCustodyRow")], """
const rows = [
  {action: 'HASH_VERIFIED', occurred_at: 'x', actor_id: 'abcdef0123', hash_verified: false},
  {action: 'HASH_VERIFIED', occurred_at: 'x', actor_id: 'abcdef0123', hash_verified: true},
  {action: 'ACQUIRED', occurred_at: 'x', actor_id: 'abcdef0123', hash_verified: null},
  {action: 'VIEWED', occurred_at: 'x', actor_id: 'abcdef0123', hash_verified: null},
];
console.log(JSON.stringify(rows.map((c) => {
  const r = renderCustodyRow(c);
  return {row: r.className, chips: r.children.slice(3).map(
    (k) => [k.className, k.textContent, k.title])};
})));
""", tmp_path)
    mismatch, verified, acquired, viewed = got
    assert mismatch["chips"][0][:2] == ["chip bad", "HASH MISMATCH"]
    assert "custody-row bad" == mismatch["row"]
    assert "integrity" in mismatch["chips"][0][2]
    assert verified["chips"][0][:2] == ["chip good", "hash verified"]
    assert acquired["chips"][0][:2] == ["chip stale", "digest recorded"]
    assert viewed["chips"] == [], "a row that attests no check claims none"
    assert "hash not checked" not in json.dumps(got)


def test_no_custody_chip_decides_on_truthiness():
    """Runs everywhere. The defect was a two-way truthiness test, which
    folds `false` into `null`; the fix compares with === on purpose."""
    js = _code()
    assert not re.search(r"hash_verified\s*\?", js), (
        "a custody chip is chosen by truthiness again: false and null "
        "would render alike")
    chip = _function("custodyHashChip")
    assert "verified === true" in chip and "verified === false" in chip
    assert "'chip bad'" in chip and "HASH MISMATCH" in chip
    assert "custodyHashChip(" in _function("renderCustodyRow")
    assert "hash not checked" not in js


# ---------------------------------------------------------------------------
# Retract: count what the projection counts, promise nothing it does not do
# ---------------------------------------------------------------------------

def test_the_retract_prompt_counts_unretracted_rows_not_the_rendered_list():
    """Counted as the projection counts live support: neither retracted
    nor superseded (the superseded half since the final review, U11,
    2026-09-23, when the projection's leg gained it)."""
    render = _function("renderAssertions")
    assert "retractAssertion(a.id, list.length)" not in render
    assert re.search(
        r"all\.filter\(\s*\(x\) => !x\.retracted_at && !x\.superseded_at"
        r" && x\.id !== a\.id\)", render), (
        "the prompt must count every row the projection counts as live")
    inspector = _function("renderInspector")
    assert "/assertions?include_retracted=true'" in inspector, (
        "the inspector must fetch the retracted rows so the count is right "
        "whatever the checkbox shows")


def test_no_string_promises_the_scrubber_brings_a_retracted_element_back():
    """The projection drops a retracted claim at every as-of position."""
    js = _code()
    for false_promise in ("as-of scrubber back", "will still show it",
                          "earlier as-of position will"):
        assert false_promise not in js, false_promise


@needs_node
def test_the_retract_prompt_says_what_will_happen_in_each_case(tmp_path):
    got = _run([_function("retractionWords")], """
console.log(JSON.stringify([
  retractionWords([], 'node', 3),
  retractionWords([], 'edge', 0),
  retractionWords([{is_correction: true}], 'node', 0),
  retractionWords([{is_correction: false}, {is_correction: true}], 'edge', 0),
]));
""", tmp_path)
    last_node, last_edge, only_edits, others = got
    assert last_node["last"] is True
    assert "LAST live assertion behind this entity" in last_node["prompt"]
    assert "3 ties drawn at it leave the canvas" in last_node["prompt"]
    for words in (last_node, last_edge):
        assert "every as-of position" in words["prompt"]
        assert "every as-of position" in words["done"]
    assert "LAST live assertion behind this tie" in last_edge["prompt"]
    assert only_edits["last"] is False
    assert ("only because 1 correction (edit note) still counts as a live "
            "assertion behind it") in only_edits["prompt"]
    assert others["prompt"].startswith("2 other live assertions remain")
    assert "stays in the graph" in others["prompt"]


# ---------------------------------------------------------------------------
# Ties: reachable without the canvas, and a pair's other ties are named
# ---------------------------------------------------------------------------

def test_a_tie_can_be_opened_from_the_inspector_and_from_the_keyboard():
    """`selectEdge` had two callers: the canvas click and edge creation."""
    js = _js()
    assert "selectEdge(id)" in _function("openFromInspector")
    assert "openFromInspector('edge', e.id)" in _function("tieButton")
    assert "renderRelationships(sel, seq)" in _function("renderInspector")
    assert "wireRelationshipKeys()" in _function("wireElementActions")
    keys = _function("wireRelationshipKeys")
    assert "canvas.addEventListener('keydown'" in keys and "'t'" in keys
    html = INDEX.read_text(encoding="utf-8")
    assert 'id="insp-rel-sec"' in html and 'id="insp-rel"' in html
    assert "T moves to the selection's" in html, "the canvas label must name T"
    assert '<span class="kbd">T</span>' in html, "the ? sheet must list T"
    # Every row carries what tells a vouch from a dispute.
    button = _function("tieButton")
    for fact in ("e.edge_type", "e.sign", "e.confidence", "e.review",
                 "e.is_inferred"):
        assert fact in button, fact
    assert "aria-label" in button
    assert js.count("function renderRelationships(") == 1


def test_the_tie_list_is_read_for_the_entity_not_cut_at_the_case_page():
    """The 2026-09-22 verifier: the undrawn rows came from `state.edges`,
    the case-wide page that stops at 1000, so a list that says "every tie"
    silently was not one in a larger case. It now reads the entity's own
    ties, drops a reply for a selection or case that has moved on, and a
    tie it found beyond the page can still be opened."""
    rel = _function("renderRelationships")
    assert "/edges?node_id=" in rel and "REL_TIE_PAGE" in rel
    assert "seq !== state.inspSeq" in rel and "caseChanged(token)" in rel
    assert "'page-full'" in rel and "'failed'" in rel
    assert "relTieCache" in _function("allTies")
    assert "relTieCache.get(sel.id)" in _function("renderInspector"), (
        "a tie found beyond the case page must open, not drop the selection")
    js = _js()
    reset = js[js.index("onCaseSwitch(() => {\n  state.inspSeq"):]
    reset = reset[:reset.index("});")]
    for cleared in ("relTieCache.clear()", "relShowAll = null", "assertLoad = null"):
        assert cleared in reset, cleared


@needs_node
def test_the_tie_list_says_what_it_cannot_vouch_for(tmp_path):
    got = _run(["const REL_TIE_PAGE = 2000;", _function("tieListNote")], """
console.log(JSON.stringify(['loading', 'failed', 'page-full', 'complete'].map(
  (s) => [tieListNote(s, 'node'), tieListNote(s, 'edge')])));
""", tmp_path)
    loading, failed, full, complete = got
    assert loading[0].startswith("Reading every tie at this entity")
    assert loading[1].startswith("Reading every tie between this pair")
    assert "first 1000" in failed[0] and "may be missing" in failed[0]
    assert failed[1].endswith("Other ties between this pair may be missing.")
    assert "first 2000 are listed" in full[0]
    assert complete == [None, None]


@needs_node
def test_parallel_ties_are_matched_in_either_direction(tmp_path):
    got = _run([_function("samePair")], """
const t = (s, d) => ({src_node_id: s, dst_node_id: d});
console.log(JSON.stringify([
  samePair(t('a', 'b'), t('a', 'b')),
  samePair(t('a', 'b'), t('b', 'a')),
  samePair(t('a', 'b'), t('a', 'c')),
]));
""", tmp_path)
    assert got == [True, True, False]


# ---------------------------------------------------------------------------
# Assertions: what is claimed, from what, by whom
# ---------------------------------------------------------------------------

@needs_node
def test_the_card_says_what_each_assertion_claims(tmp_path):
    got = _run([_deceptive(), _function("visibleText"),
                _function("claimValueText"), _function("claimLine")], """
console.log(JSON.stringify([
  claimLine({is_correction: true, claim_path: 'label',
             claim_value: {label: 'viper'}}, 'node'),
  claimLine({is_correction: true, claim_path: null,
             claim_value: {weight: 0.5, confidence: 'HIGH'}}, 'edge'),
  claimLine({is_correction: false, claim_path: 'comms.tox',
             claim_value: 'AB\\u202ECD'}, 'node'),
  claimLine({is_correction: false, claim_path: null, claim_value: null}, 'edge'),
]));
""", tmp_path)
    assert got[0] == 'Correction: label → "viper"'
    assert got[1] == "Correction: weight → 0.5, confidence → \"HIGH\""
    # An attacker-published value is de-fanged, never rendered raw.
    assert got[2] == 'Claims comms.tox is "AB‹U+202E›CD"'
    assert got[3] == "Claims this tie as recorded"


def test_the_card_names_its_author_exhibit_and_document():
    render = _function("renderAssertions")
    assert "a.created_by_name" in render, "the author is a name, not a hash"
    assert "a.evidence_title" in render and "focusEvidence(a.evidence_id)" in render
    assert "a.document_id" in render
    # Every part appended: `appendChild(...parts)` takes the FIRST alone,
    # which is how the source's name went missing on the first try.
    assert "for (const part of documentFacts(a)) src.appendChild(part);" in render
    assert "appendChild(..." not in _code()
    assert "a.is_correction ? 'Correction'" in render
    # The Evidence section lists both routes and says which assertion.
    linked = _function("renderLinkedEvidence")
    assert "backingLine(b)" in linked
    assert "focusAssertionCard(b.assertion_id)" in _function("backingLine")


@needs_node
def test_the_card_names_the_document_and_source_only_when_given(tmp_path):
    """The server returns a document title and a source name only under
    the Collected documents list's rule; the card uses them when present
    and falls back to the copyable ids, de-fanging the forum's own text."""
    got = _run([_deceptive(), _function("visibleText"),
                "function copyable(node, value, label) {"
                " return {wrap: node.textContent, cls: node.className,"
                " title: node.title, value: value, label: label}; }",
                _function("documentFacts")], """
const D = 'd0c0000011112222', S = '5c0000003333444';
console.log(JSON.stringify([
  documentFacts({document_id: D, document_title: 'Re: \u202Econtact', source_id: S,
                 source_name: 'exploit.in'}),
  documentFacts({document_id: D, document_title: '', source_id: S, source_name: 'xss.is'}),
  documentFacts({document_id: D, document_title: null, source_id: S, source_name: null}),
  documentFacts({document_id: null, source_id: S, source_name: 'breach.vc'}),
]));
""", tmp_path)
    named, untitled, withheld, source_only = got
    assert named[0]["wrap"] == "Document: Re: ‹U+202E›contact"
    assert named[0]["value"] == "d0c0000011112222"
    assert named[1]["textContent"] == "from exploit.in"
    assert untitled[0]["wrap"] == "Document: (untitled)"
    assert withheld[0]["wrap"] == "document d0c00000"
    assert "collection.read" in withheld[0]["title"]
    assert withheld[1]["wrap"] == "source 5c000000"
    assert [p.get("textContent") for p in source_only] == ["from breach.vc"]


@needs_node
def test_a_missing_assertion_card_is_explained_by_what_actually_happened(tmp_path):
    """The 2026-09-22 verifier: "Show assertion" always blamed the
    checkbox, including while the section was loading or had failed."""
    got = _run([_function("assertionNotListedWords")], """
const key = 'node:n1';
const rows = [{id: 'a1', retracted_at: null, superseded_at: 'T'},
              {id: 'a2', retracted_at: 'T', superseded_at: null},
              {id: 'a3', retracted_at: null, superseded_at: null}];
console.log(JSON.stringify([
  assertionNotListedWords('a1', null, key, false),
  assertionNotListedWords('a1', {key: key, all: null, failed: false}, key, false),
  assertionNotListedWords('a1', {key: 'node:old', all: rows, failed: false}, key, false),
  assertionNotListedWords('a1', {key: key, all: null, failed: true}, key, false),
  assertionNotListedWords('a1', {key: key, all: rows, failed: false}, key, false),
  assertionNotListedWords('a2', {key: key, all: rows, failed: false}, key, false),
  assertionNotListedWords('a9', {key: key, all: rows, failed: false}, key, false),
]));
""", tmp_path)
    none, loading, stale, failed, superseded, retracted, gone = got
    for words in (none, loading, stale):
        assert "still loading" in words
    assert "could not be loaded" in failed
    assert superseded.startswith("It is superseded") and "Include retracted" in superseded
    assert retracted.startswith("It is retracted")
    assert "not among the assertions read" in gone
    assert "Include retracted" not in failed + loading + gone
