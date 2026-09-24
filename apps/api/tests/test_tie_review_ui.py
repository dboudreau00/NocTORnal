"""The tie inspector's Review section: the console half of gap-tie-review.

gap-tie-review and ux05-inspector:review-state-never-leaves-proposed
(2026-09-23). Nothing could move `core.edge.review`, so every tie read
"review PROPOSED", the canvas ringed every node, and the Metrics row
"Unreviewed proposals" always equalled "Ties in projection" while its
tooltip told the analyst to dispose of something no control could.
`test_tie_review_pg.py` holds the server half (born state, the audited
route, its refusals); this file holds the console: the section exists on a
tie and only there, it asks for a note where the server will, it posts to
the route, and a review recounts the rings the canvas draws.

Pure: reads the shipped static assets, as `test_ui_invariants.py` does,
and runs the section's pure functions and the ring recount under Node
(skipped where Node is not installed).
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


def _const(name: str) -> str:
    js = _js()
    start = js.index(f"const {name} = ")
    end = js.index("\n};", start) + 3 if js[js.index("=", start) + 2] == "{" \
        else js.index(";\n", start) + 2
    return js[start:end]


_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)


def _run(script: str) -> dict:
    if not NODE:
        pytest.skip("Node is not installed here")
    run = subprocess.run([NODE, "-"], input=script, capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


# ---------------------------------------------------------------------------
# The markup
# ---------------------------------------------------------------------------

def test_the_review_section_exists_hidden_with_its_three_verbs():
    html = _html()
    sec = html[html.index('<section id="insp-review-sec"'):]
    sec = sec[:sec.index("</section>")]
    assert 'class="insp-sec" hidden' in sec, "hidden until a tie is selected"
    for element_id in ("insp-review-state", "insp-review-says",
                       "insp-review-history", "review-note", "review-accept",
                       "review-dispute", "review-reopen", "review-error"):
        assert f'id="{element_id}"' in sec, element_id
    assert 'id="review-error" class="form-error" role="alert"' in sec
    assert 'maxlength="2000"' in sec, "the server's own cap on a note"


def test_the_review_follows_the_claims_and_the_exhibits():
    """A disposal is made having read why the tie is believed."""
    html = _html()
    body = html[html.index('<div id="insp-body"'):]
    assert (body.index('id="insp-assertions"') < body.index('id="insp-evidence"')
            < body.index('id="insp-review-sec"'))


# ---------------------------------------------------------------------------
# The wiring
# ---------------------------------------------------------------------------

def test_the_inspector_shows_the_review_on_a_tie_and_only_there():
    body = _fn("renderInspector")
    assert "tie = e;" in body
    assert body.index("const seq = ++state.inspSeq;") < body.index(
        "syncTieReview(sel, tie, seq);")
    sync = _fn("syncTieReview")
    assert "sel.kind === 'edge'" in sync
    assert "show($('insp-review-sec'), tie);" in sync
    assert "api(cpath('/graph/edges/' + sel.id + '/review'))" in sync
    assert "$('review-note').value = ''" in sync, (
        "a note typed about one tie must not be sent for the next")


def test_a_review_posts_to_the_route_and_checks_the_note_first():
    body = _fn("submitTieReview")
    assert "cpath('/graph/edges/' + edgeId + '/review')" in body
    assert "method: 'POST', json: { review: review, note: note || null }" in body
    assert body.index("reviewNoteProblem(") < body.index("await api(")
    assert "sel.id !== edgeId" in body, "never sent for another tie"
    assert "caseChanged(token)" in body
    assert "applyTieReview(edgeId, out.review)" in body and "draw();" in body
    assert "err.status === 403" in body and "proposal.review" in body


def test_every_verb_button_is_wired():
    js = _js()
    assert "wireTieReview();" in _fn("wireElementActions")
    verbs = _const("REVIEW_VERBS")
    for verb, element_id in (("ACCEPTED", "review-accept"),
                             ("DISPUTED", "review-dispute"),
                             ("PROPOSED", "review-reopen")):
        assert f"['{verb}', '{element_id}']" in verbs
    assert "submitTieReview(verb)" in _fn("wireTieReview")
    assert re.search(r"onCaseSwitch\(\(\) => \{\s*tieReview\.edgeId = null;", js)


def test_the_metrics_row_names_the_control_that_clears_it():
    body = _fn("renderNodeMetrics")
    assert "Accept or Dispute it under Review" in body


# ---------------------------------------------------------------------------
# Behaviour, under Node
# ---------------------------------------------------------------------------

def test_the_words_and_the_note_rule():
    script = "\n".join([
        "const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];",
        "const NO_TIME = 'not recorded';",
        _fn("pad2"), _fn("fmtTime"),
        "function visibleText(s) { return String(s); }",
        "function shortId(id) { return id ? id.slice(0, 8) : 'unknown'; }",
        _const("REVIEW_WORDS"), _fn("reviewNoteProblem"), _fn("reviewDoneWords"),
        _fn("reviewEventWords"), _fn("reviewOriginWords"),
        """console.log(JSON.stringify({
  words: Object.keys(REVIEW_WORDS),
  dispute: reviewNoteProblem('DISPUTED', ''),
  reopen: reviewNoteProblem('PROPOSED', ''),
  accept: reviewNoteProblem('ACCEPTED', ''),
  noted: reviewNoteProblem('DISPUTED', 'the handle is reused'),
  done: ['ACCEPTED', 'DISPUTED', 'PROPOSED'].map(reviewDoneWords),
  event: reviewEventWords({review: 'ACCEPTED', previous: 'PROPOSED',
    note: 'two captures agree', by_name: 'Ana Analyst',
    at: '2026-09-23T14:02:00Z'}),
  bare: reviewEventWords({review: 'DISPUTED', by: 'abcdef0123', at: '2026-09-23T14:02:00Z'}),
  born: reviewOriginWords({created_by_name: 'Ana Analyst', created_at: '2026-09-20T09:00:00Z'}),
  triage: reviewOriginWords({created_by_name: 'Ana Analyst', created_at: '2026-09-20T09:00:00Z',
    accepted_from_triage_by: 'Rae Reviewer', accepted_from_triage_at: '2026-09-21T10:30:00Z'}),
}));"""])
    got = _run(script)
    assert got["words"] == ["PROPOSED", "ACCEPTED", "DISPUTED"]
    assert "needs a note" in got["dispute"] and "needs a note" in got["reopen"]
    assert got["accept"] is None and got["noted"] is None
    assert all(w.startswith(("Accepted", "Disputed", "Reopened")) for w in got["done"])
    assert got["event"] == ("ACCEPTED by Ana Analyst, 2026-09-23 14:02 UTC "
                            "(was PROPOSED): two captures agree")
    assert got["bare"] == "DISPUTED by abcdef01, 2026-09-23 14:02 UTC."
    assert got["born"] == ("In this state since it was entered by Ana Analyst, "
                           "2026-09-20 09:00 UTC. Nobody has reviewed it since.")
    assert got["triage"] == ("Accepted from a Triage proposal by Rae Reviewer, "
                             "2026-09-21 10:30 UTC.")


def test_a_review_recounts_the_rings_the_canvas_draws():
    """The tie half of the ring is `state.nodeUnreviewed`, counted by
    `indexProjection` from the projection's ties (the Triage half,
    `state.nodeProposed`, is the queue's). Accepting one tie takes one off
    each end; the count at an end with another waiting tie stays above
    zero."""
    script = "\n".join([
        "const CONF_RANK = { LOW: 0, MODERATE: 1, HIGH: 2 };",
        "const relTieCache = new Map();",
        """const state = {
  gedges: [
    {id: 't1', src_node_id: 'a', dst_node_id: 'b', confidence: 'LOW', review: 'PROPOSED'},
    {id: 't2', src_node_id: 'a', dst_node_id: 'c', confidence: 'LOW', review: 'PROPOSED'},
    {id: 't3', src_node_id: 'b', dst_node_id: 'c', confidence: 'LOW', review: 'ACCEPTED'},
  ],
  edges: [{id: 't1', review: 'PROPOSED'}],
};""",
        _fn("indexProjection"), _fn("applyTieReview"),
        """indexProjection();
const before = Object.fromEntries(state.nodeUnreviewed);
applyTieReview('t1', 'ACCEPTED');
const after = Object.fromEntries(state.nodeUnreviewed);
console.log(JSON.stringify({before, after, list: state.edges[0].review}));"""])
    got = _run(script)
    assert got["before"] == {"a": 2, "b": 1, "c": 1}
    assert got["after"] == {"a": 1, "c": 1}, "b's ring clears, a's does not"
    assert got["list"] == "ACCEPTED", "the case's tie list follows too"


def test_a_tie_waiting_on_a_person_is_marked_and_listed_first():
    """The entity's "Ties awaiting review" row sends the analyst to
    Relationships to open each PROPOSED tie. ux08-triage had taken the
    review off the row while nothing wrote the column, and the merge kept
    that removal, so the tie to open could not be told from the rest, and
    on a hub it sat behind "Show all N ties". A PROPOSED or DISPUTED tie is
    marked and spoken, an ACCEPTED one is not, and among the drawn ties
    the PROPOSED ones come first."""
    script = "\n".join([
        _fn("tieReviewFlag"),
        "function tieEndLabel(e, end) { return end === 'src' ? e.src_node_id : e.dst_node_id; }",
        _fn("tieOrder"),
        """const recs = [
  {drawn: true, e: {src_node_id: 'hub', dst_node_id: 'amy', edge_type: 'KNOWS', review: 'ACCEPTED'}},
  {drawn: false, e: {src_node_id: 'hub', dst_node_id: 'bob', edge_type: 'KNOWS', review: 'PROPOSED'}},
  {drawn: true, e: {src_node_id: 'hub', dst_node_id: 'zed', edge_type: 'KNOWS', review: 'PROPOSED'}},
  {drawn: true, e: {src_node_id: 'hub', dst_node_id: 'cal', edge_type: 'KNOWS', review: 'DISPUTED'}},
];
recs.sort(tieOrder('hub'));
console.log(JSON.stringify({
  flags: ['PROPOSED', 'DISPUTED', 'ACCEPTED', undefined].map(tieReviewFlag),
  order: recs.map((r) => r.e.dst_node_id),
}));"""])
    got = _run(script)
    proposed, disputed, accepted, missing = got["flags"]
    assert proposed["flag"] == "PROPOSED" and "awaiting a person" in proposed["spoken"]
    assert disputed["flag"] == "DISPUTED" and "DISPUTED" in disputed["spoken"]
    assert accepted is None and missing is None, "an ACCEPTED tie is not marked"
    assert got["order"] == ["zed", "amy", "cal", "bob"], (
        "drawn ties first, the PROPOSED ones ahead of the rest")
    button = _fn("tieButton")
    assert "tieReviewFlag(e.review)" in button
    assert "'tie-flag review-' + e.review" in button
    assert "(review ? review.spoken : '')" in button, "the flag is spoken too"


def test_the_section_carries_no_dash_a_reader_sees():
    js = _js()
    region = js[js.index("/* ── inspector: a tie's review"):js.index(
        "/* A note typed about case A's tie")]
    code = re.sub(r"/\*.*?\*/", "", region, flags=re.S)
    assert "\u2014" not in code and "\u2013" not in code and " -- " not in code
