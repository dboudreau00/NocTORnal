"""The Feeds pane after the ux12-feeds review (2026-09-22, fixed 2026-09-23).

The review found a pane that could be looked at and not worked: a queue
row's score named no selector, copies from one partner read as a second
source, nothing could be opened, dismissed or attached, the Category
filter shrank to itself and followed the analyst into the next case, dead
letters named no feed and were the same list in every case, the Keys tab
flagged a key as somebody else's and offered no Revoke, Poll now was one
unconfirmed click the server would refuse, and the rail badge was never
set. Each is held here.

Pure, like `test_ui_invariants.py`: these read the shipped static assets.
The checks marked `needs_node` EXECUTE the shipped functions under Node,
because "a resend is not called corroboration" is a claim about what the
function returns; they skip where Node is absent. The server halves are
in `test_feeds_review_pg.py`.
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


def _visible(html: str) -> str:
    return re.sub(r"<!--.*?-->", "", html, flags=re.S)


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first column-0 `}`."""
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    js = _js()
    m = re.search(r"(?m)^const " + re.escape(name) + r" = ", js)
    assert m, f"const {name} is gone"
    return js[m.start():js.index("};", m.start()) + 2]


_STUBS = """
function visibleText(s) { return s === null || s === undefined ? '' : String(s); }
function fmtTime(x) { return 'T(' + x + ')'; }
function countOf(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }
function agree(n, one, many) { return Number(n) === 1 ? one : many; }
function num(v, dp) { const n = Number(v); return dp === undefined ? String(n) : n.toFixed(dp); }
const NO_VALUE = 'not recorded';
"""


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text(_STUBS + "\n".join(sources) + "\n" + body,
                      encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# ux12-feeds:also-sent-by-false-corroboration
# ---------------------------------------------------------------------------

def _src(feed, copies, this_feed):
    return {"feed": feed, "copies": copies, "this_feed": this_feed}


@needs_node
def test_a_resend_from_one_feed_is_not_called_a_second_source(tmp_path):
    rows = [
        {"feed": "demo partner feed", "duplicate_count": 1,
         "duplicate_sources": [_src("demo partner feed", 1, True)]},
        {"feed": "A", "duplicate_count": 2,
         "duplicate_sources": [_src("A", 2, True)]},
        {"feed": "A", "duplicate_count": 3,
         "duplicate_sources": [_src("B", 1, False), _src("C", 2, False)]},
        {"feed": "A", "duplicate_count": 1,
         "duplicate_sources": [_src("B", 1, False)]},
        {"feed": "A", "duplicate_count": 2, "duplicate_sources": []},
        {"feed": "A", "duplicate_count": 1, "duplicate_sources": []},
    ]
    got = _run([_fn("copiesText")], "console.log(JSON.stringify("
               + json.dumps(rows) + ".map(copiesText)));", tmp_path)
    assert got == [
        "1 copy, all from this feed: a resend, not a second source",
        "2 copies, all from this feed: resends, not a second source",
        "3 copies, from 2 other feeds: B, C",
        "1 copy, from another feed: B",
        "2 copies you cannot see, from feeds not shown here",
        "1 copy you cannot see, from a feed not shown here",
    ]
    assert all("also sent by" not in g for g in got)


@needs_node
def test_a_copy_the_reader_cannot_see_is_never_called_a_resend(tmp_path):
    """The fix round's case (2026-09-23): one readable resend and one copy
    the reader cannot see printed "2 copies, all from this feed: a resend,
    not a second source; 1 copy you cannot see", denying corroboration
    about the copy nobody here can read. Near-duplicate matching runs
    across the deployment, so unseen copies are the ordinary case."""
    rows = [
        {"feed": "A", "duplicate_count": 2,
         "duplicate_sources": [_src("A", 1, True)]},
        {"feed": "A", "duplicate_count": 3,
         "duplicate_sources": [_src("A", 1, True), _src("B", 2, False)]},
        {"feed": "A", "duplicate_count": 4,
         "duplicate_sources": [_src("A", 2, True), _src("B", 1, False)]},
        {"feed": "A", "duplicate_count": 3,
         "duplicate_sources": [_src("B", 1, False), _src("C", 1, False)]},
    ]
    got = _run([_fn("copiesText")], "console.log(JSON.stringify("
               + json.dumps(rows) + ".map(copiesText)));", tmp_path)
    assert got == [
        "2 copies: 1 resent by this feed; 1 you cannot see, from a feed "
        "not shown here",
        "3 copies: 1 resent by this feed; 2 from another feed (B)",
        "4 copies: 2 resent by this feed; 1 from another feed (B); 1 you "
        "cannot see, from a feed not shown here",
        "3 copies: 2 from 2 other feeds (B, C); 1 you cannot see, from a "
        "feed not shown here",
    ]
    for text in got:
        assert "not a second source" not in text, (
            "a mix of resends and other or unseen copies was called a resend")


def test_the_queue_help_no_longer_calls_a_copy_another_feed():
    html = " ".join(_visible(_html()).split())
    assert "how many other feeds sent the same" not in html
    assert "a resend, not a second source" in html
    assert "'also sent by'" not in _js()


@needs_node
def test_a_folded_copy_sits_directly_under_its_primary(tmp_path):
    got = _run([_fn("foldUnderPrimaries")], """
const rows = [
  {id: 'd1', is_duplicate: true, duplicate_of: 'p1'},   // sorts above it
  {id: 'p1', is_duplicate: false},
  {id: 'x', is_duplicate: false},
  {id: 'd2', is_duplicate: true, duplicate_of: 'gone'},  // primary unlisted
  {id: 'd3', is_duplicate: true, duplicate_of: 'd1'},   // a copy of a copy
];
console.log(JSON.stringify(foldUnderPrimaries(rows).map(
  (r) => r.id + (r.folded_under ? '>' : ''))));
""", tmp_path)
    assert got == ["p1", "d1>", "d3>", "x", "d2"], (
        "copies are not placed under the record they fold into, or one was "
        "lost")


# ---------------------------------------------------------------------------
# ux12-feeds:watched-hit-unnamed-and-contradicted
# ---------------------------------------------------------------------------

@needs_node
def test_every_term_of_a_score_is_said_with_its_selector_and_watch(tmp_path):
    got = _run([_fn("scoreTerms")], """
console.log(JSON.stringify([
  scoreTerms({watched_selector_hits: 1, terms: [
    {term: 'selector', points: 10, selector: 'northgate.example',
     watches: [{name: 'nightjar-selectors'}]},
    {term: 'category', points: 2, category: 'STEALER_LOG'}]}),
  scoreTerms({terms: [{term: 'selector', points: 10, hidden: true}]}),
  scoreTerms({watched_selector_hits: 1}),
  scoreTerms({terms: [{term: 'duplicate', points: -8}]}),
]));
""", tmp_path)
    assert got[0] == ["+10 selector northgate.example (watch nightjar-selectors)",
                      "+2 high-risk category STEALER_LOG"]
    assert got[1] == ["+10 a selector watched on a case you are not on"]
    assert "Rescore" in got[2][0], "an old count must say how to name it"
    assert got[3] == ["-8 folded duplicate"]


@needs_node
def test_a_watch_on_another_case_is_flagged_with_that_case(tmp_path):
    """A quarantined record is scored against every watch, so a term can
    come from a watch on a case other than the record's: it says which."""
    got = _run([_fn("scoreTerms")], """
function caseCodesText(ids) { return ids.map((i) => 'CODE-' + i).join(', '); }
const d = {terms: [{term: 'selector', points: 10, selector: 's.example',
                    watches: [{name: 'w', case_id: 'c1'}]}]};
console.log(JSON.stringify([scoreTerms(d, null), scoreTerms(d, 'c1')]));
""", tmp_path)
    assert got == [["+10 selector s.example (watch w on CODE-c1)"],
                   ["+10 selector s.example (watch w)"]]


def test_the_row_prints_the_terms_not_a_bare_count():
    row = _code(_fn("ingestRow"))
    assert "scoreTerms(r.priority_detail, r.case_id)" in row
    assert "' watched selector hit'" not in row


def test_collected_says_it_is_the_polls_and_points_at_the_queue():
    html = " ".join(_visible(_html()).split())
    assert "Watch hits: what this case's polls matched" in html
    assert "what fired on this case" not in html
    hits = _fn("loadWatchHits")
    assert "No watch has matched anything on this case yet." not in hits
    assert "are in the Ingest" in hits


# ---------------------------------------------------------------------------
# ux12-feeds:queue-is-a-dead-end
# ---------------------------------------------------------------------------

def test_a_queue_row_can_be_opened_triaged_and_attached():
    row = _code(_fn("ingestRow"))
    for verb in ("'Open'", "'Mark triaged'", "'Link\u2026'",
                 "'Discard\u2026'", "'Back to new'", "'Attach to case\u2026'"):
        assert verb in row, f"the queue row lost {verb}"
    assert "'/ingest/records/' + r.id + '/attach'" in row
    assert "'/ingest/records/' + r.id + '/triage'" in _fn("applyTriage")
    assert "api('/ingest/records/' + r.id)" in _fn("toggleRecordDetail")


def test_open_never_asks_for_a_payload_value():
    detail = _code(_fn("toggleRecordDetail"))
    assert "d.payload_shape" in detail
    assert "d.payload)" not in detail and "d.payload." not in detail


def test_the_queue_defaults_to_what_needs_triage():
    html = _html()
    sel = html[html.index('id="ing-triage"'):]
    sel = sel[:sel.index("</select>")]
    assert '<option value="NEW" selected>Needs triage</option>' in sel
    assert "params.set('triage_state', tri)" in _fn("loadIngestQueue")


# ---------------------------------------------------------------------------
# ux12-feeds:category-filter-collapses-and-sticks
# ---------------------------------------------------------------------------

def test_category_options_come_from_the_whole_queue():
    load = _code(_fn("loadIngestQueue"))
    assert "paintCategoryOptions(facets)" in load
    assert "body.records.map((r) => r.category)" not in load, (
        "the options are rebuilt from the page the filter narrowed")
    paint = _code(_fn("paintCategoryOptions"))
    assert "facets.categories" in paint
    assert "cats.push(keep)" in paint, "a chosen filter vanishes from its select"


def test_the_filters_reset_on_a_case_switch():
    js = _js()
    resets = [m.start() for m in re.finditer(r"onCaseSwitch\(\(\) => \{", js)]
    bodies = [js[s:js.index("\n});", s)] for s in resets]
    assert any("resetIngestFilters()" in b for b in bodies)
    reset = _fn("resetIngestFilters")
    assert "$('ing-category')" in reset and "sel.value = ''" in reset
    assert "$('ing-triage').value = 'NEW'" in reset


def test_a_filtered_empty_queue_says_it_is_filtered():
    text = _fn("ingestEmptyText")
    assert "cat + ' records'" in text and "in all." in text
    assert "ing-clear-filter" in _fn("loadIngestQueue")


# ---------------------------------------------------------------------------
# ux12-feeds:feeds-badge-never-set
# ---------------------------------------------------------------------------

def test_the_feeds_badge_is_set_and_counted_on_case_open():
    assert "$('feeds-badge')" in _fn("paintFeedsBadge")
    assert "watched_untriaged" in _fn("paintFeedsBadge")
    assert "refreshFeedsBadge();" in _code(_fn("openCase"))
    badge = _fn("refreshFeedsBadge")
    assert "limit: '1'" in badge
    assert "badgeRefusedFor = state.userId" in badge, (
        "a refused badge read is asked again on every case open, humming "
        "AUTHZ_DENIED")


# ---------------------------------------------------------------------------
# ux12-feeds:dead-letters-no-feed-no-scope
# ---------------------------------------------------------------------------

def test_a_dead_letter_names_its_feed_key_and_case():
    row = _code(_fn("deadLetterRow"))
    for needle in ("fact('feed'", "fact('key id'", "fact('case'",
                   "'not attached to any case'", "d.resolution"):
        assert needle in row, f"deadLetterRow lost {needle}"


def test_dead_letters_open_on_this_case_and_say_what_was_withheld():
    load = _code(_fn("loadDeadLetters"))
    assert "params.set('case_id', state.caseId)" in load
    assert "params.set('api_key_id', feed)" in load
    assert "dead_letter_rate_24h" in load
    assert "paintDlWithheld(body.scope" in load
    assert "unattached_withheld" in _fn("paintDlWithheld")
    assert "renderDlGroups(rows)" in load


def test_a_dead_letter_can_be_repaired_and_replayed():
    row = _code(_fn("deadLetterRow"))
    assert "'Repair and replay\u2026'" in row
    assert "'/ingest/dead-letters/' + d.id + '/replay'" in row
    assert "!d.replayed_at && !d.fragment_withheld" in row
    # The original stays on the card above the repair.
    assert row.index("'fragment mono-sm'") < row.index("Repair and replay")


def test_replay_is_offered_only_to_a_reader_the_server_would_let_replay():
    """Fix round (2026-09-23): every reader was offered it and a REVIEWER
    met a 403 inside the form."""
    row = _code(_fn("deadLetterRow"))
    assert "if (d.can_replay && !d.replayed_at" in row
    # `replayTargets` offers no case unless `intoCase` (r2 c19 moved the
    # choice there; test_ingest_replay_key_secret_ui.py runs it).
    assert "DL.intoCase, codeOf)" in row, (
        "an operator who may replay into quarantine only is offered a case")
    load = _code(_fn("loadDeadLetters"))
    assert "DL.intoCase = Boolean(body.scope && body.scope.replay_into_case)" in load
    assert load.index("DL.intoCase =") < load.index("renderList('dl-list'")
    assert "rows.some((d) => d.can_replay)" in load
    assert "'repair and replay them: analysts and lead investigators can'" in load


# ---------------------------------------------------------------------------
# ux12-feeds:poll-now-one-click-and-blocked
# ---------------------------------------------------------------------------

def test_poll_now_is_confirmed_and_names_what_it_touches():
    row = _code(_fn("dueRow"))
    confirm = row.index("window.confirm(")
    assert confirm < row.index("'/collection/sources/' + s.id + '/run'"), (
        "the poll is sent before it is confirmed")
    for needle in ("host", "No persona", "no egress profile",
                   "requests per second"):
        assert needle in row[confirm:], f"the confirm does not say {needle}"


def test_poll_now_is_off_while_the_server_would_refuse_it():
    row = _code(_fn("dueRow"))
    assert "srcRun.allowed === false" in row and "srcRun.ready === false" in row
    assert "run.disabled = true" in row
    paint = _code(_fn("paintRunState"))
    assert "run.blocking" in paint and "src-run-readiness" in paint
    assert "srcRun = b.run" in _fn("loadSources")


def test_a_reader_who_may_not_poll_is_told_why_in_the_pane():
    """Fix round (2026-09-23): a non-collector saw greyed Poll now buttons
    whose only reason was a title on a disabled control, which a keyboard
    never reaches and a touch screen never shows."""
    paint = _code(_fn("paintRunState"))
    assert "run.allowed === false" in paint
    assert "collector role" in paint
    assert "box.classList.toggle('warn'" in paint, (
        "a reader who simply does not poll is shown a warning")


# ---------------------------------------------------------------------------
# ux12-feeds:mixed-unlabelled-timezones (the due line says how long ago)
# ---------------------------------------------------------------------------

@needs_node
def test_a_due_time_says_how_long_ago_it_passed(tmp_path):
    got = _run([_fn("dueAgo")], """
const now = Date.now();
console.log(JSON.stringify([
  dueAgo(new Date(now - 3 * 3600 * 1000).toISOString()),
  dueAgo(new Date(now - 5 * 60 * 1000).toISOString()),
  dueAgo(null),
]));
""", tmp_path)
    assert got == [", 3 hours ago", ", 5 minutes ago", ""]
    assert "fmtTime(s.due_at) + dueAgo(s.due_at)" in _fn("dueRow")


# ---------------------------------------------------------------------------
# ux12-feeds:confidence-label-ambiguous
# ---------------------------------------------------------------------------

@needs_node
def test_the_category_guess_is_said_in_words(tmp_path):
    got = _run([_const("CATEGORY_SOURCE_WORDS"), _fn("categoryGuessText")], """
console.log(JSON.stringify([categoryGuessText(0.7, 'STRUCTURE'),
                            categoryGuessText(0.8, 'STRUCTURE_NESTED')]));
""", tmp_path)
    assert got == ["70% from its structure", "80% from its nested structure"]


def test_the_row_labels_a_category_guess_and_offers_a_correction():
    row = _code(_fn("ingestRow"))
    assert "fact('category guess'" in row
    assert "fact('confidence'" not in row
    assert "'Correct category\u2026'" in row
    assert "'/ingest/records/' + r.id + '/category'" in row
    assert "r.category_was" in row, "the classifier's output is not kept"


# ---------------------------------------------------------------------------
# ux12-feeds:keys-tab-read-only
# ---------------------------------------------------------------------------

def test_a_live_key_can_be_revoked_with_a_reason_and_a_confirm():
    row = _code(_fn("keyRow"))
    assert "'/revoke'" in row and "reason: why.trim()" in row
    assert row.index("window.confirm(") < row.index("'/revoke'")
    assert "withStepUp(" in row
    assert "if (!k.revoked_at)" in row


def test_a_key_can_be_issued_and_its_secret_shows_once():
    issue = _code(_fn("issueKey"))
    assert "api('/ingest/keys'" in issue and "withStepUp(" in issue
    assert "renderKeySecret(out" in issue
    secret = _fn("renderKeySecret")
    assert "Shown once" in secret and "credRow('Ingest key', out.secret)" in secret
    assert "clear($('key-secret-out'))" in _fn("clearSessionSecrets"), (
        "an issued key outlives the session that was shown it")
    html = _html()
    assert 'id="key-issue-form"' in html and 'id="key-secret-out"' in html


def test_the_issue_form_starts_again_at_unknown_after_a_key_is_issued():
    """Fix round (2026-09-23): `form.reset()` put the category select,
    whose options are built at run time, back on its FIRST option, so the
    next key was offered as STEALER_LOG."""
    issue = _code(_fn("issueKey"))
    assert "resetKeyForm();" in issue
    assert "$('key-issue-form').reset();" not in issue
    reset = _code(_fn("resetKeyForm"))
    assert "$('key-issue-form').reset();" in reset
    assert reset.index(".reset();") < reset.index("cat.value = 'UNKNOWN'")


# ---------------------------------------------------------------------------
# ux12-feeds:suppressed-hits-no-response
# ---------------------------------------------------------------------------

def test_a_watch_hit_can_be_suppressed_or_unsuppressed():
    row = _code(_fn("watchHitRow"))
    assert "'/unsuppress'" in row and "'/suppress'" in row
    assert "json: { reason: why.trim() }" in row
    assert row.index("if (h.suppressed)") < row.index("'/unsuppress'")


# ---------------------------------------------------------------------------
# ux12-feeds:rescore-silent
# ---------------------------------------------------------------------------

def test_rescore_says_what_changed_and_there_is_a_rescore_all():
    one = _code(_fn("rescoreRecord"))
    assert "out.priority_before" in one and "'Rescored: unchanged at '" in one
    assert "ING.flash" in one
    flash = _code(_fn("showIngestFlash"))
    assert "scrollIntoView" in flash, "the row is not kept in view"
    assert "api('/ingest/records/rescore'" in _fn("rescoreAll")
    assert 'id="ing-rescore-all"' in _html()
