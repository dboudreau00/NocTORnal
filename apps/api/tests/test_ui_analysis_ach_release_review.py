"""The Analysis and ACH panes, held to the Alpha 6 release review
(2026-09-24). Pure: no database. The node halves skip when node is not
installed; the static checks still run.

- c11: a DISPUTED tie was counted nowhere, so a removal set resting on
  ties a reviewer doubts read "All 58 ties have been reviewed" as a calm
  note;
- c17: moving the as-of time while a first Run (or a stored-run read) was
  in flight drew the old instant's numbers under the new graph;
- c18: with every hypothesis ruled out, the matrix said nothing had been
  scored beside cards that counted the stances;
- u13: the "Score an assertion" picker kept the previous case's assertion
  after a switch, with Score enabled;
- u14: the trend was not re-read after a run, so it left out the run just
  computed;
- x-ach-withheld: the ACH pane never said that evidence above the reader
  had been left out.

The server halves are in test_analytics_leads_and_coverage.py (c11, c16),
test_ach.py (c18) and test_ach_release_review_pg.py (c18 over HTTP and
x-ach-withheld).
"""
from __future__ import annotations

from test_ui_analysis_pane import _PRELUDE, _const, _fn, _html, _js, _run, _src

# ---------------------------------------------------------------------------
# c17: the projection moving under a Run or a stored-run read
# ---------------------------------------------------------------------------

def _asof_harness() -> str:
    return _PRELUDE + r"""
function anQuery() { const q = new URLSearchParams({ preset: state.proj.preset });
  if (state.proj.as_of) q.set('as_of', state.proj.as_of); return q; }
function syncAnalysisSizeOptions() {}
let drawn = 0;
function renderAnalytics() { drawn += 1; }
function storedRunStatus() { return 'Showing the run of x.'; }
function loadKeyPlayer() {}
function loadMetricHistory() {}
""" + _const("AN_PROJECTION_CHANGED") + "\n" + "\n".join(
    _fn(n) for n in ("countOf", "agree", "closeClause", "analysisFailureText",
                     "blankAnalytics", "runAnalysis", "loadLatestAnalysis")) + "\n"


def test_an_as_of_move_during_a_first_run_retires_its_reply():
    """Nothing was on screen, so nothing bumped the generation: the suite
    for the old instant passed every guard and was drawn beside the graph
    at the new one, and the Node size control offered its betweenness."""
    got = _run(_asof_harness() + r"""
(async () => {
  $('an-kpp-n').value = '3';
  runAnalysis(); await tick();
  const suite = take('/analytics?');
  out.askedAt = suite.path;
  state.proj.as_of = '2025-02-02T22:04:00Z';          // the timeline moved
  suite.resolve({ run_id: 's-old', current: true, computed_at_ms: 17 });
  await tick(); await tick(); await tick();
  out.analytics = state.analytics || null;
  out.drawn = drawn;
  out.kppAsked = calls.some((c) => c.path.includes('/key-player'));
  out.status = $('an-status').textContent;
  out.empty = $('an-empty').textContent;
  out.running = state.analyticsRunning;
  out.button = $('an-run').disabled;
  console.log(JSON.stringify(out));
})();
""")
    assert "as_of" not in got["askedAt"]
    assert got["analytics"] is None, "the old instant's run was kept for the new graph"
    assert got["drawn"] == 0 and not got["kppAsked"], got
    assert "computed in" not in got["status"], got["status"]
    assert "computing" not in got["status"], "the dropped run left 'computing...' behind"
    assert "projection changed" in got["empty"]
    assert got["running"] is False and got["button"] is False


def test_a_drag_that_comes_back_to_the_same_instant_keeps_the_run():
    """Compared when the reply lands, not bumped on every move: a timeline
    dragged away and back again asks the same question."""
    got = _run(_asof_harness() + r"""
(async () => {
  $('an-kpp-n').value = '3';
  runAnalysis(); await tick();
  const suite = take('/analytics?');
  state.proj.as_of = '2025-02-02T22:04:00Z';
  state.proj.as_of = null;
  suite.resolve({ run_id: 's-now', current: true, computed_at_ms: 17 });
  await tick(); await tick();
  take('/analytics/key-player?').resolve({ run_id: 'k', key_player: { n_remove: 3 } });
  await tick(); await tick();
  out.run = state.analytics && state.analytics.run_id;
  out.status = $('an-status').textContent;
  console.log(JSON.stringify(out));
})();
""")
    assert got["run"] == "s-now"
    assert got["status"].startswith("unchanged since the last run") or "computed in" in got["status"]


def test_an_as_of_move_during_a_stored_run_read_retires_its_reply():
    got = _run(_asof_harness() + r"""
(async () => {
  $('an-kpp-n').value = '3';
  loadLatestAnalysis(); await tick();
  const read = take('/analytics/latest?');
  state.proj.as_of = '2025-02-02T22:04:00Z';
  read.resolve({ run_id: 's-old', current: true, computed_at: '2026-09-24T07:51:00Z' });
  await tick(); await tick();
  out.analytics = state.analytics || null;
  out.drawn = drawn;
  console.log(JSON.stringify(out));
})();
""")
    assert got["analytics"] is None and got["drawn"] == 0, got


def test_both_in_flight_guards_compare_the_projection_they_were_asked_under():
    for name in ("runAnalysis", "loadLatestAnalysis"):
        body = _fn(name)
        assert "anQuery().toString() !== q.toString()" in body, name
        # The query is taken before the guard that reads it.
        assert body.index("const q = anQuery();") < body.index("const stale = ")


# ---------------------------------------------------------------------------
# u14: the trend re-read when a run lands
# ---------------------------------------------------------------------------

def _trend_harness() -> str:
    return _PRELUDE + r"""
function anQuery() { return new URLSearchParams({ preset: 'all' }); }
function syncAnalysisSizeOptions() {}
function renderAnalytics() {}
function storedRunStatus() { return 'Showing the run of x.'; }
function loadKeyPlayer() {}
const reread = [];
function loadMetricHistory(node, label) { reread.push([node, label]); }
""" + _const("AN_PROJECTION_CHANGED") + "\n" + "\n".join(
    _fn(n) for n in ("countOf", "agree", "closeClause", "analysisFailureText",
                     "blankAnalytics", "runAnalysis", "loadLatestAnalysis")) + "\n"


def test_a_run_that_lands_re_reads_the_open_trend():
    """The series was fetched when Trend was pressed and only re-filtered
    after a run, so 'rv_alpha: 3 runs' stayed at three with the run just
    computed missing from the chart and the table."""
    got = _run(_trend_harness() + r"""
(async () => {
  $('an-kpp-n').value = '3';
  state.analyticsHistory = { series: [{}, {}, {}] };
  state.analyticsHistoryNode = 'n-alpha'; state.analyticsHistoryLabel = 'rv_alpha';
  runAnalysis(); await tick();
  take('/analytics?').resolve({ run_id: 's4', current: true, computed_at_ms: 5 });
  await tick(); await tick();
  take('/analytics/key-player?').resolve({ run_id: 'k', key_player: { n_remove: 3 } });
  await tick(); await tick();
  out.afterRun = reread.slice();
  // No trend open: nothing is spent.
  state.analyticsHistory = null; state.analyticsHistoryNode = null;
  runAnalysis(); await tick();
  take('/analytics?').resolve({ run_id: 's5', current: true, computed_at_ms: 5 });
  await tick(); await tick();
  take('/analytics/key-player?').resolve({ run_id: 'k', key_player: { n_remove: 3 } });
  await tick(); await tick();
  out.closed = reread.length;
  // A stored run read back while a trend is open re-reads it too.
  state.analytics = null; state.analyticsQuery = '';
  state.analyticsHistory = { series: [] };
  state.analyticsHistoryNode = 'n-beta'; state.analyticsHistoryLabel = 'rv_beta';
  loadLatestAnalysis(); await tick();
  take('/analytics/latest?').resolve({ run_id: 's6', current: true,
    computed_at: '2026-09-24T07:51:00Z' });
  await tick(); await tick();
  out.stored = reread.slice(1);
  console.log(JSON.stringify(out));
})();
""")
    assert got["afterRun"] == [["n-alpha", "rv_alpha"]], got
    assert got["closed"] == 1, "a run with no trend open fetched one"
    assert got["stored"] == [["n-beta", "rv_beta"]], got


# ---------------------------------------------------------------------------
# u13: the ACH scorer across a case switch
# ---------------------------------------------------------------------------

def _ach_pick_harness() -> str:
    return _PRELUDE + r"""
const BASES = [['DIRECT_OBSERVATION', 'Direct observation']];
function selectionLabel() { return 'umbra_shrike'; }
function rememberAssertion() {}
function inlineProblem(box, err) { box.textContent = String(err); }
""" + "\n".join(_fn(n) for n in ("assertionOptionLabel", "updateAchScoreControls",
                                 "loadAchEvidenceOfSelection")) + "\n"


def test_a_scorer_load_answered_after_a_switch_is_not_offered_in_the_new_case():
    got = _run(_ach_pick_harness() + r"""
(async () => {
  state.selection = { kind: 'node', id: 'n1' };
  loadAchEvidenceOfSelection(); await tick();
  const read = take('/nodes/n1/assertions');
  state.caseSeq += 1; state.caseId = 'case-b';          // the analyst switched
  read.resolve([{ id: 'a1', basis: 'DIRECT_OBSERVATION', reliability: 'C',
    credibility: '3', rationale: 'handle umbra_shrike posting in Bastion crew threads' }]);
  await tick(); await tick();
  out.options = $('ach-evidence-pick').children.length;
  out.of = $('ach-evidence-of').textContent;
  console.log(JSON.stringify(out));
})();
""")
    assert got["options"] == 0 and got["of"] == "", got


def test_the_case_switch_empties_the_scorer():
    """NIGHTJAR's assertion, its grading and its AMBER rationale stayed in
    the picker under WHEATEAR's header with Score enabled, and saving it
    was refused as if the assertion had been retracted."""
    got = _run(_ach_pick_harness() + "\n" + _fn("resetAchScorer") + r"""
$('ach-evidence-pick').value = 'a1';
$('ach-evidence-pick').disabled = false;
$('ach-evidence-pick').appendChild(el('option', null, 'Direct observation, C3'));
$('ach-evidence-hyp').value = 'h1';
$('ach-evidence-hyp').disabled = false;
$('ach-evidence-of').textContent = 'umbra_shrike, 1 live assertion';
$('ach-evidence-msg').textContent = 'x'; $('ach-evidence-msg').hidden = false;
$('ach-evidence-add').disabled = false;
resetAchScorer();
out.pick = { value: $('ach-evidence-pick').value, disabled: $('ach-evidence-pick').disabled,
  options: $('ach-evidence-pick').children.map((o) => o.textContent) };
out.hyp = { value: $('ach-evidence-hyp').value, disabled: $('ach-evidence-hyp').disabled };
out.of = $('ach-evidence-of').textContent;
out.msg = $('ach-evidence-msg').hidden;
out.add = $('ach-evidence-add').disabled;
console.log(JSON.stringify(out));
""")
    assert got["pick"]["value"] == "" and got["pick"]["disabled"], got
    assert got["pick"]["options"] == ["Load the selected element's assertions first"]
    assert got["hyp"]["value"] == "" and got["hyp"]["disabled"], got
    assert got["of"] == "" and got["msg"] is True
    assert got["add"] is True, "Score stayed enabled on the previous case's assertion"
    # Registered as a case-switch reset, and the picker's placeholder is the
    # one the markup ships with, so a fresh page and a switched one agree.
    js = _js()
    assert "onCaseSwitch(() => {\n  if (_stanceCtx) closeStanceChooser();" in js
    reset = js[js.index("onCaseSwitch(() => {\n  if (_stanceCtx) closeStanceChooser();"):]
    assert "resetAchScorer();" in reset[:reset.index("\n});")]
    assert "Load the selected element's assertions first" in _html()


# ---------------------------------------------------------------------------
# c11: a disputed tie is not settled
# ---------------------------------------------------------------------------

def test_disputed_ties_warn_and_are_named_beside_the_numbers():
    """The verifier's reproduction: 58 ties, none proposed, 5 disputed. The
    readout said "reviewed 58 of 58", the flag was a calm note and it read
    "All 58 ties behind these numbers have been reviewed"."""
    got = _run(_PRELUDE + _src("reviewCoverageText", "decayWords") + r"""
out.disputed = reviewCoverageText({ ties: 58, proposed: 0, accepted: 53, disputed: 5,
  rejected: 0, evidenced: 40 });
out.one = reviewCoverageText({ ties: 58, proposed: 0, accepted: 57, disputed: 1,
  rejected: 0, evidenced: 40 });
out.both = reviewCoverageText({ ties: 58, proposed: 2, accepted: 51, disputed: 5,
  rejected: 0, evidenced: 40 });
out.settled = reviewCoverageText({ ties: 58, proposed: 0, accepted: 58, disputed: 0,
  rejected: 0, evidenced: 40 });
out.legacy = reviewCoverageText({ ties: 3, proposed: 0, evidenced: 1, rejected: 0 });
console.log(JSON.stringify(out));
""")
    d = got["disputed"]
    assert "have been reviewed" not in d, d
    assert d.startswith("No tie behind these numbers is an unreviewed proposal, "
                        "and 40 of 58 rest on an exhibit.")
    assert "5 of 58 ties are disputed in review and still count here." in d
    assert d.endswith("Treat the brokers and the removal set named here as leads "
                      "until those disputes are settled.")
    assert "1 of 58 ties is disputed in review and still counts here." in got["one"]
    assert got["one"].endswith("until that dispute is settled.")
    assert got["both"].startswith("2 of 58 ties behind these numbers are unreviewed")
    assert got["both"].endswith("until those ties are reviewed and the disputes settled.")
    assert got["settled"].startswith("All 58 ties behind these numbers have been reviewed")
    assert "dispute" not in got["settled"] and "leads" not in got["settled"]
    # A payload with no count (the server works it out for stored runs, so
    # this is only a defensive read) is read as none, not as NaN.
    assert "NaN" not in got["legacy"] and "undefined" not in got["legacy"]

    flags = _fn("renderAnalyticsFlags")
    assert "rc.proposed || rc.disputed || rc.rejected ? 'warn' : 'note'" in flags
    render = _fn("renderAnalytics")
    assert "(rc.disputed ? ', disputed ' + rc.disputed : '')" in render


def test_every_coverage_clause_agrees_with_its_own_count():
    """The fix round's slip (2026-09-24): one proposal beside one dispute
    closed with "until those ties are reviewed and the disputes settled",
    because that branch was written for the plural and the first test only
    tried five disputes. Swept over none, one and several of each count, so
    no clause can be worded for one number and shown beside another."""
    got = _run(_PRELUDE + _src("reviewCoverageText", "decayWords") + r"""
out.rows = [];
for (const proposed of [0, 1, 2]) for (const disputed of [0, 1, 2])
  for (const rejected of [0, 1, 2]) for (const evidenced of [0, 1, 2]) {
    const ties = 58;
    out.rows.push({ proposed, disputed, rejected, evidenced,
      text: reviewCoverageText({ ties, proposed, disputed, rejected, evidenced,
        accepted: ties - proposed - disputed - rejected }) });
  }
out.verifier = reviewCoverageText({ ties: 58, proposed: 2, accepted: 55, disputed: 1,
  rejected: 0, evidenced: 40 });
out.single = reviewCoverageText({ ties: 1, proposed: 0, accepted: 1, disputed: 0,
  rejected: 0, evidenced: 1 });
console.log(JSON.stringify(out));
""")
    # The verifier's own case, word for word.
    assert got["verifier"].endswith(
        "until those ties are reviewed and the dispute settled."), got["verifier"]
    assert got["single"] == ("The one tie behind these numbers has been reviewed, "
                             "and 1 of 1 rests on an exhibit."), got["single"]
    assert len(got["rows"]) == 81
    for r in got["rows"]:
        t, p, d, x, e = r["text"], r["proposed"], r["disputed"], r["rejected"], r["evidenced"]
        where = f"proposed={p} disputed={d} rejected={x} evidenced={e}: {t}"
        assert "NaN" not in t and "undefined" not in t, where
        assert "  " not in t and ".." not in t, where
        # The exhibit clause.
        assert f" {e} of 58 {'rests' if e == 1 else 'rest'} on an exhibit." in t, where
        # The proposals, where they are counted and where they are closed.
        if p == 1:
            assert "1 of 58 ties behind these numbers is an unreviewed proposal" in t, where
            assert "that tie is reviewed" in t and "those ties" not in t, where
        elif p:
            assert f"{p} of 58 ties behind these numbers are unreviewed proposals" in t, where
            assert "those ties are reviewed" in t and "that tie" not in t, where
        else:
            assert "reviewed and" not in t and "tie is reviewed" not in t, where
        # The disputes, counted and closed.
        if d == 1:
            assert "1 of 58 ties is disputed in review and still counts here." in t, where
            assert "disputes" not in t, where
            assert ("the dispute settled." in t) == bool(p), where
            assert ("that dispute is settled." in t) == (not p), where
        elif d:
            assert f"{d} of 58 ties are disputed in review and still count here." in t, where
            assert "the dispute " not in t and "that dispute" not in t, where
        else:
            assert "dispute" not in t, where
        # Leads only while something is unsettled.
        assert ("as leads until" in t) == bool(p or d), where
        if x == 1:
            assert "1 tie was rejected in review and still counts here." in t, where
        elif x:
            assert f"{x} ties were rejected in review and still count here." in t, where
        # Nothing claims every tie was reviewed while one is open or doubted.
        assert ("have been reviewed" in t) == (not p and not d), where


# ---------------------------------------------------------------------------
# c18: every hypothesis ruled out
# ---------------------------------------------------------------------------

def test_a_row_with_no_live_hypothesis_says_so_rather_than_nothing_scored():
    got = _run(_PRELUDE + _src("achAnd", "achUnknownWhy") + r"""
out.none = achUnknownWhy({ assessed_against: 0 }, 0, []);
out.one = achUnknownWhy({ assessed_against: 1 }, 2, ['H2']);
console.log(JSON.stringify(out));
""")
    assert "No live hypothesis is left to score this item against" in got["none"]
    assert "scored against no hypotheses" not in got["none"]
    assert "kept for the record" in got["none"]
    assert "only one hypothesis" in got["one"] and "Still to score: H2." in got["one"]


# ---------------------------------------------------------------------------
# x-ach-withheld: what the matrix left out
# ---------------------------------------------------------------------------

def test_the_ach_pane_says_what_was_left_out_in_words():
    got = _run(_PRELUDE + _src("achWithheldText", "renderAchWarnings") + r"""
out.count = achWithheldText({ incomplete: true, mode: 'COUNT', evidence: 3 });
out.single = achWithheldText({ incomplete: true, mode: 'COUNT', evidence: 1 });
out.presence = achWithheldText({ incomplete: true, mode: 'PRESENCE' });
out.clean = achWithheldText({ incomplete: false, mode: 'COUNT' });
out.silent = achWithheldText(undefined);
renderAchWarnings({ withheld: { incomplete: true, mode: 'PRESENCE' },
  warnings: ['Only one hypothesis.'] });
out.box = $('ach-warnings').children.map((p) => [p.className, p.textContent]);
console.log(JSON.stringify(out));
""")
    assert got["count"].startswith("3 items of evidence in this case's matrix rest on "
                                   "material above your clearance or outside your "
                                   "compartments. They are left out of every cell")
    assert got["single"].startswith("1 item of evidence in this case's matrix rests on")
    assert " It is left out of every cell" in got["single"]
    assert got["presence"].startswith("Some of the evidence in this case's matrix rests on")
    assert "a blank cell may be one you cannot see" in got["presence"]
    assert got["clean"] == "" and got["silent"] == ""
    # First in the warnings, above the method's own caveats.
    assert got["box"][0][0] == "help warn" and got["box"][0][1] == got["presence"]
    assert got["box"][1][1] == "Only one hypothesis."


# ---------------------------------------------------------------------------
# Copy rules for everything added here
# ---------------------------------------------------------------------------

def test_the_new_copy_has_no_dashes_or_bracketed_plurals():
    import re
    for name in ("reviewCoverageText", "achUnknownWhy", "achWithheldText",
                 "resetAchScorer", "renderAnalytics", "renderAnalyticsFlags"):
        body = _fn(name)
        code = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        strings = re.findall(r"'((?:[^'\\]|\\.)*)'", code)
        assert strings, name
        for s in strings:
            assert chr(0x2014) not in s and chr(0x2013) not in s, (name, s)
            assert " -- " not in s, (name, s)
            assert not re.search(r"\w\(s\)", s), (name, s)
