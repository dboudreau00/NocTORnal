"""The Analysis pane's Roles card: CONCOR positions (F1, 2026-09-24).

Behavioural where it matters: the shipped loader and renderer run under
node with the fake DOM of `test_ui_analysis_pane.py`, whose prelude and
extractors this file imports. The rule `test_ui_case_switch_and_dates.py`
holds for every loader (a case token, and a reply for a case left is
dropped) is asserted here for `loadConcor` rather than by editing that
file's list. The server halves are `test_blockmodel.py`,
`test_concor_pg.py` and `test_concor_http_pg.py`.

Pure: no database. The node halves skip when node is not installed.
"""
from __future__ import annotations

import re

from test_ui_analysis_pane import _PRELUDE, _const, _fn, _html, _js, _run, _src


def _loader() -> str:
    return _PRELUDE + r"""
const renders = [];
function renderConcor() { renders.push(JSON.parse(JSON.stringify(state.analyticsConcor))); }
const defanged = [];
function safeLabelsDeep(x) { defanged.push(x); return x; }
$('an-concor-depth').value = '2';
state.analytics = { run_id: 'suite-1' }; state.analyticsQuery = 'preset=all';
""" + _src("analysisFailureText", "loadConcor", "onConcorDepthChange")


def test_the_roles_card_reads_the_stored_run_first_and_computes_on_run():
    got = _run(_loader() + r"""
(async () => {
  // Opening the pane on a stored run reads, and never computes.
  loadConcor(true); await tick();
  out.firstAsk = calls.map((c) => c.path);
  take('/analytics/concor/latest?preset=all&depth=2').reject(new ApiError(404, 'Not found', ''));
  await tick(); await tick();
  out.missing = state.analyticsConcor;
  out.computedOnOpen = calls.some((c) => c.path.includes('/analytics/concor?'));
  // A Run reads the stored run, and computes because the graph moved.
  loadConcor(false); await tick();
  take('/analytics/concor/latest?preset=all&depth=2').resolve({ run_id: 'old',
    current: false });
  await tick(); await tick();
  take('/analytics/concor?preset=all&depth=2').resolve({ run_id: 'roles-2', current: true,
    concor: { positions: [] }, nodes: [] });
  await tick(); await tick();
  out.after = state.analyticsConcor.run_id;
  out.renders = renders;
  // A stored run that still holds is used as it is.
  loadConcor(false); await tick();
  take('/analytics/concor/latest').resolve({ run_id: 'kept', current: true });
  await tick(); await tick();
  out.kept = state.analyticsConcor.run_id;
  out.spent = calls.length;
  console.log(JSON.stringify(out));
})();
""")
    assert got["firstAsk"] == ["/cases/case-a/analytics/concor/latest?preset=all&depth=2"]
    assert got["missing"] == {"missing": True, "depth": 2}
    assert not got["computedOnOpen"], "opening the pane spent a metered role analysis"
    assert got["after"] == "roles-2"
    # It says it is reading while it reads, and finding once it computes.
    assert {"pending": True, "reading": True, "depth": 2} in got["renders"]
    assert {"pending": True, "depth": 2} in got["renders"]
    assert got["kept"] == "kept" and got["spent"] == 0


def _run_harness() -> str:
    return _PRELUDE + r"""
function anQuery() { return new URLSearchParams({ preset: 'all' }); }
function syncAnalysisSizeOptions() {}
const order = [];
function renderAnalytics() { order.push('drawn'); }
function loadConcor(storedOnly) { order.push('roles:' + storedOnly); return new Promise(() => {}); }
function storedRunStatus() { return 'Showing the run of x.'; }
function loadKeyPlayer(storedOnly) { order.push('kpp:' + storedOnly); }
function loadMetricHistory() {}
""" + _const("AN_PROJECTION_CHANGED") + "\n" + "\n".join(
        _fn(n) for n in ("countOf", "agree", "closeClause", "analysisFailureText",
                         "blankAnalytics", "runAnalysis", "loadLatestAnalysis")) + "\n"


def test_the_suite_and_key_player_are_drawn_before_roles_is_asked():
    got = _run(_run_harness() + r"""
(async () => {
  $('an-kpp-n').value = '3';
  runAnalysis(); await tick();
  take('/analytics?').resolve({ run_id: 's', current: true, computed_at_ms: 5 });
  await tick(); await tick();
  take('/analytics/key-player?').resolve({ run_id: 'k', key_player: {} });
  await tick(); await tick();
  out.run = order.slice();
  // The role analysis never finishes here, and the Run finished anyway.
  out.status = $('an-status').textContent;
  out.running = !!state.analyticsRunning;
  order.length = 0;
  blankAnalytics('x');
  loadLatestAnalysis(); await tick();
  take('/analytics/latest?').resolve({ run_id: 's2', current: true,
    computed_at: '2026-09-24T10:00:00Z' });
  await tick(); await tick();
  out.stored = order.slice();
  console.log(JSON.stringify(out));
})();
""")
    assert got["run"] == ["drawn", "roles:false"], got["run"]
    assert got["status"].startswith("computed in"), got["status"]
    assert not got["running"], "the Run waited on the role analysis"
    assert got["stored"] == ["drawn", "kpp:true", "roles:true"], got["stored"]
    body = _fn("runAnalysis")
    assert "await loadConcor" not in body and "loadConcor(false);" in body


def test_a_depth_change_fetches_only_the_roles_card():
    got = _run(_loader() + r"""
(async () => {
  $('an-concor-depth').value = '3';
  onConcorDepthChange(); await tick();
  out.asked = calls.map((c) => c.path);
  console.log(JSON.stringify(out));
})();
""")
    assert got["asked"] == ["/cases/case-a/analytics/concor/latest?preset=all&depth=3"]
    assert "$('an-concor-depth').addEventListener('change', onConcorDepthChange);" in _js()
    wire = _fn("onConcorDepthChange")
    assert "loadConcor(false)" in wire and "blankAnalytics" not in wire
    html = _html()
    assert '<select id="an-concor-depth" class="select">' in html
    assert '<option value="2" selected>2 splits, up to 4 positions</option>' in html
    assert '<option value="4">4 splits, up to 16 positions</option>' in html


def test_a_late_roles_reply_never_draws_over_the_depth_on_screen():
    got = _run(_loader() + r"""
(async () => {
  loadConcor(false); await tick();
  const two = take('/analytics/concor/latest?preset=all&depth=2');
  $('an-concor-depth').value = '3';
  onConcorDepthChange(); await tick();
  take('/analytics/concor/latest?preset=all&depth=3').resolve({ run_id: 'd3', current: true,
    concor: { depth: 3 } });
  await tick(); await tick();
  two.resolve({ run_id: 'd2', current: true, concor: { depth: 2 } });
  await tick(); await tick();
  out.shown = state.analyticsConcor.run_id;
  console.log(JSON.stringify(out));
})();
""")
    assert got["shown"] == "d3", "the reply for the old depth drew over the new one"


def test_loadConcor_takes_a_case_token_and_drops_a_reply_for_a_case_left():
    got = _run(_loader() + r"""
(async () => {
  loadConcor(false); await tick();
  const ask = take('/analytics/concor/latest');
  state.caseSeq += 1;                              // the analyst left the case
  ask.resolve({ run_id: 'other-case', current: true });
  await tick(); await tick();
  out.shown = state.analyticsConcor;
  out.more = calls.length;
  console.log(JSON.stringify(out));
})();
""")
    assert got["shown"] == {"pending": True, "reading": True, "depth": 2}
    assert got["more"] == 0
    body = _fn("loadConcor")
    assert "const token = caseToken();" in body and "caseChanged(token)" in body


def test_the_case_switch_clears_the_roles_card():
    js = _js()
    switch = js[js.index("onCaseSwitch(() => {\n  blankAnalytics(AN_EMPTY_TEXT);"):]
    switch = switch[:switch.index("\n});")]
    assert "'an-concor'" in switch
    blank = _fn("blankAnalytics")
    assert "state.analyticsConcor = null;" in blank
    assert "state.analyticsConcorAll = {};" in blank


def test_the_roles_payload_goes_through_safeLabelsDeep():
    got = _run(_loader() + r"""
(async () => {
  loadConcor(false); await tick();
  const payload = { run_id: 'r', current: true, concor: { positions: [] }, nodes: [] };
  take('/analytics/concor/latest').resolve(payload);
  await tick(); await tick();
  out.defanged = defanged.some((x) => x && x.run_id === 'r');
  console.log(JSON.stringify(out));
})();
""")
    assert got["defanged"]
    assert "state.analyticsConcor = safeLabelsDeep(roles);" in _fn("loadConcor")


_CARD_FNS = ("andList", "typeName", "pctOf", "ageText", "concorFitText",
             "concorImageTable", "actorButton", "graphButton", "pairsWithin",
             "pairKey", "renderConcor")


def _card() -> str:
    return _PRELUDE + r"""
state.nodeTypeMeta = new Map([['FORUM', { display_name: 'Forum' }]]);
const shown = [];
function showSetOnGraph(spec) { shown.push(spec); }
function selectTab() {} function selectNode() {} function renderFocusFlag() {}
function loadConcor() {}
""" + _src(*_CARD_FNS) + r"""
const member = (k) => ({ id: 'n' + k, label: 'E' + k, node_type: 'IDENTITY' });
function roles(over) {
  return { run_id: 'roles-1', current: true, computed_at: '2026-09-24T10:00:00Z',
    nodes: [member(1), member(2), member(3)].map((m, i) => ({ ...m, position: i < 2 ? 'A' : 'B' })),
    concor: { positions: [
        { position: 'A', block: '1.1', block_index: 0, size: 2, members: [member(1), member(2)] },
        { position: 'B', block: '1.2', block_index: 1, size: 1, members: [member(3)] }],
      relations: [{ key: 'positive', label: 'positive ties', ties: 3 }],
      density: { positive: [[0.0, 1.0], [0.5, null]] },
      image: { positive: [[0, 1], [1, 0]] }, alpha: { positive: 0.5 },
      r_squared: { positive: 0.64, overall: 0.64 }, all_converged: true,
      max_iterations: 50, unsplit: [], equivalent_pairs: [],
      no_ties: { count: 0 }, profile_only: { count: 0, types: [] },
      derived_ties_counted_whole: false, reading: 'R.', method: 'M.', ...(over || {}) } };
}
function paint(r) { state.analyticsConcor = r; renderConcor(); return text($('an-concor')); }
"""


def test_a_weak_fit_and_an_unmeasurable_fit_are_worded():
    got = _run(_card() + r"""
out.strong = paint(roles());
out.weak = paint(roles({ r_squared: { positive: 0.1, overall: 0.1 } }));
out.none = paint(roles({ r_squared: { positive: null, overall: null } }));
out.unsettled = paint(roles({ all_converged: false }));
out.derived = paint(roles({ derived_ties_counted_whole: true }));
out.only = paint(roles({ profile_only: { count: 2, types: ['FORUM'] }, no_ties: { count: 1 } }));
console.log(JSON.stringify(out));
""")
    assert ("CONCOR placed 3 entities with ties in 2 positions. The positions account "
            "for 64% of the pattern of ties, a strong fit.") in got["strong"]
    assert "a weak fit." in got["weak"]
    assert "Read the positions as a sorting, not a finding." in got["weak"]
    assert "Read the positions as a sorting" not in got["strong"]
    assert ("How well the positions account for the ties cannot be measured here: the "
            "positions predict the same density for every pair of entities.") in got["none"]
    assert "did not settle within 50 rounds" in got["unsettled"]
    assert "a derived tie counts here as a whole tie" in got["derived"]
    assert "2 vertices that are not entities (Forum) shape who is alike but hold no " \
           "position." in got["only"]
    assert "1 entity with no tie in this view has no position." in got["only"]
    assert "From the role run of 2026-09-24 10:00 UTC" in got["strong"]


def test_positions_can_be_shown_on_the_graph_and_the_flag_names_the_roles_run():
    got = _run(_card() + _src("setFocusSource") + r"""
state.gedges = [{ src_node_id: 'n1', dst_node_id: 'n2' }, { src_node_id: 'n2', dst_node_id: 'n3' }];
paint(roles());
const buttons = $('an-concor').querySelectorAll('button')
  .filter((b) => b.textContent === 'Show on graph');
buttons[0].click();
const spec = shown[0];
out.spec = { label: spec.label, fromConcor: spec.fromConcor, lit: [...spec.lit],
             pairs: [...spec.pairs], note: spec.note };
const focus = { fromConcor: true, runId: 'roles-1' };
out.fresh = setFocusSource(focus);
state.analyticsConcor.current = false;
out.stale = setFocusSource(focus);
state.analyticsConcor = null;
out.gone = setFocusSource(focus);
console.log(JSON.stringify(out));
""")
    spec = got["spec"]
    assert spec["label"] == "position A" and spec["fromConcor"] is True
    assert spec["lit"] == ["n1", "n2"] and spec["pairs"] == ["n1|n2"]
    assert "They need not be tied to each other." in spec["note"]
    assert got["fresh"] == "from the Analysis pane"
    assert got["stale"] == "from an analysis run the graph has changed since"
    assert got["gone"] == "from an analysis run no longer on the Analysis pane"
    assert "fromConcor: !!spec.fromConcor" in _fn("showSetOnGraph")


def test_the_currency_check_marks_a_stale_roles_run():
    got = _run(_card() + r"""
out.stale = paint({ ...roles(), current: false });
out.fresh = paint(roles());
console.log(JSON.stringify(out));
""")
    assert ("The graph has changed since this role run. Run the analysis again to "
            "recompute it.") in got["stale"]
    assert "has changed" not in got["fresh"]
    body = _fn("checkAnalysisCurrency")
    assert "if (asked(roles)) q.append('run_id', roles.run_id);" in body
    assert "if (asked(roles) && state.analyticsConcor === roles) {" in body


def test_the_image_table_colours_through_classes_not_inline_style():
    got = _run(_card() + r"""
paint(roles());
const cells = [];
function walkAll(n) { for (const c of n.children || []) { if (c.tag === 'td') cells.push(c);
  walkAll(c); } }
walkAll($('an-concor'));
const captions = [];
function caps(n) { for (const c of n.children || []) { if (c.tag === 'caption') captions.push(c.textContent); caps(c); } }
caps($('an-concor'));
out.cells = cells.map((c) => ({ text: text(c), shaded: [...c.classList.s] }));
out.captions = captions;
console.log(JSON.stringify(out));
""")
    shaded = [c for c in got["cells"] if "on-positive" in c["shaded"]]
    assert [c["text"] for c in shaded] == ["1.000 tied", "0.500 tied"], got["cells"]
    # An unshaded block carries no mark: the words carry what the colour does.
    assert all("tied" not in c["text"] for c in got["cells"] if not c["shaded"]
               or "on-positive" not in c["shaded"])
    assert got["captions"] == [
        "Density of positive ties from each position (rows) to each position (columns). "
        "Blocks marked tied are at least 0.500, the density of positive ties among these "
        "entities."]
    for name in ("renderConcor", "concorImageTable"):
        assert ".style" not in _fn(name) and "style=" not in _fn(name)


def test_the_inspector_names_the_position_when_the_roles_run_placed_the_entity():
    got = _run(_PRELUDE + r"""
function communityNo() { return null; }
function selectTab() {}
""" + _src("renderInspectorAnalysis") + r"""
state.analytics = { node_count: 3, nodes: [{ id: 'n1', betweenness_rank: 1,
  constraint: null }] };
state.analyticsConcor = { nodes: [{ id: 'n1', position: 'B' }] };
renderInspectorAnalysis('n1');
out.placed = text($('insp-an-brief'));
state.analyticsConcor = null;
renderInspectorAnalysis('n1');
out.none = text($('insp-an-brief'));
console.log(JSON.stringify(out));
""")
    assert "Position B in the role analysis." in got["placed"]
    assert "role analysis" not in got["none"]


def test_the_roles_copy_names_no_actor_and_obeys_the_copy_rules():
    body = _fn("renderConcor") + _fn("concorImageTable") + _fn("concorFitText")
    strings = re.findall(r"'(?:[^'\\\n]|\\.)*'", body)
    for s in strings:
        assert not re.search(r"\bactors?\b", s, flags=re.I), s
        for bad in ("\u2014", "\u2013", " -- ", "(s)"):
            assert bad not in s, s
    html = _html()
    assert "<h3 class=\"h3\">Roles: entities in the same position</h3>" in html
    assert html.index('id="an-cohesion"') < html.index('id="an-concor"') \
        < html.index('id="an-balance"')
    assert "'Finding positions...'" in body and "'Looking for stored positions...'" in body
    assert _const("AN_PROJECTION_CHANGED")      # the pane's shared note is untouched
