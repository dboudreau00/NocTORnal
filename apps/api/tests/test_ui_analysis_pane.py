"""The Analysis pane, held to the 2026-09-22 usability review (lens
ux10-analytics), finding by finding.

Behavioural where it matters: the shipped functions run under node with a
fake DOM and a canvas context that records what is drawn, the harness shape
of `test_ui_case_state_races.py`. Static checks hold the wiring the harness
does not run. The server half of each finding is in
`test_analytics_leads_and_coverage.py` (pure) and
`test_analytics_latest_pg.py` (database).

Pure: no database. The node halves skip when node is not installed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"
APP_CSS = STATIC / "app.css"


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8").replace("\r\n", "\n")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    """A top-level const, up to the `;` that closes its statement."""
    js = _js()
    m = re.search(rf"^const {re.escape(name)} = ", js, flags=re.M)
    assert m, f"app.js has no top-level const {name}"
    end = js.index(";\n", m.start())
    return js[m.start():end + 2]


def _node_binary() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    win = Path("C:/Program Files/nodejs/node.exe")
    return str(win) if win.exists() else None


def _run(script: str) -> dict:
    node = _node_binary()
    if not node:
        pytest.skip("node is not installed; the static checks still run")
    res = subprocess.run([node, "-"], input=script, capture_output=True,
                         text=True, encoding="utf-8", env=dict(os.environ),
                         timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


#: A fake DOM with what the pane's renderers touch, a canvas context that
#: records its calls, and an `api` whose replies the test lands.
_PRELUDE = r"""
const nodes = {};
function mk(tag, id) {
  const n = { tag, id, value: '', checked: false, hidden: false, disabled: false,
    textContent: '', className: '', title: '', children: [], dataset: {}, attrs: {},
    handlers: {}, scrolled: null, focused: false, tabIndex: tag === 'button' ? 0 : -1,
    classList: { s: new Set(), add(c) { this.s.add(c); }, remove(c) { this.s.delete(c); },
      contains(c) { return this.s.has(c); },
      toggle(c, on) { if (on) this.s.add(c); else this.s.delete(c); } },
    appendChild(c) { this.children.push(c); return c; },
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
    addEventListener(t, f) { (this.handlers[t] = this.handlers[t] || []).push(f); },
    click() { for (const f of this.handlers.click || []) f({ stopPropagation() {} }); },
    scrollIntoView(o) { this.scrolled = o; },
    focus(o) { this.focused = o || true; },
    querySelectorAll(sel) { return walk(this).filter((x) => matches(x, sel)); },
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null; } };
  return n;
}
function walk(n) { const out = []; for (const c of n.children || []) { out.push(c); out.push(...walk(c)); } return out; }
function matches(x, sel) {
  if (sel === 'tr') return x.tag === 'tr';
  if (sel === 'button[aria-pressed]') return x.tag === 'button' && 'aria-pressed' in x.attrs;
  if (sel === 'button') return x.tag === 'button';
  return false;
}
function $(id) { if (!nodes[id]) nodes[id] = mk('div', id); return nodes[id]; }
function el(tag, cls, text) { const n = mk(tag, null); n.className = cls || '';
  if (text !== undefined && text !== null) n.textContent = String(text); return n; }
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function setMsg(n, text) { n.textContent = text || ''; n.hidden = !text; }
function text(n) { return (n.textContent || '') + (n.children || []).map(text).join(''); }
function opts(select, pairs, selected) {
  clear(select);
  for (const [value, label] of pairs) { const o = el('option', null, label); o.value = value; select.appendChild(o); }
  const hit = pairs.find(([v]) => v === selected);
  select.value = hit ? hit[0] : (pairs.length ? pairs[0][0] : '');
}
const document = { createTextNode(t) { return { tag: '#text', textContent: String(t), children: [] }; },
  querySelectorAll(sel) {
    if (sel === '#an-table th[data-sort]') return ths;
    return [];
  } };
const ths = ['label', 'degree', 'vouches', 'betweenness', 'constraint',
             'effective_size', 'community'].map((k) => { const t = mk('th', null); t.dataset.sort = k; return t; });
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail; }
}
const state = { caseId: 'case-a', caseSeq: 1, proj: { preset: 'all', min_confidence: 'LOW',
  include_inferred: true, as_of: null }, analyticsGen: 0, gnodes: [], gedges: [],
  sizeMetric: 'degree', metrics: {}, analyticsHistory: null };
function caseToken() { return state.caseSeq; }
function caseChanged(t) { return t !== state.caseSeq; }
function cpath(p) { return '/cases/' + state.caseId + p; }
const calls = [];
function api(path, o) { return new Promise((resolve, reject) => calls.push({ path, o, resolve, reject })); }
function take(fragment) {
  const i = calls.findIndex((c) => c.path.includes(fragment));
  if (i < 0) throw new Error('no call for ' + fragment + ' in ' + JSON.stringify(calls.map((c) => c.path)));
  return calls.splice(i, 1)[0];
}
const failed = [];
function fail(err) { failed.push(String(err && err.title || err)); }
const tick = () => new Promise((r) => setImmediate(r));
function debounce(fn) { return (...a) => fn(...a); }
function safeLabelsDeep(x) { return x; }
function visibleText(s) { return String(s); }
function hueClass() { return 'hue-actor'; }
function pad2(n) { return String(n).padStart(2, '0'); }
const NO_TIME = 'not set';
const NO_VALUE = 'not recorded';
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const reduceMotion = true;
const PAINT = { surface2: 's2', grid: 'grid', accent: 'accent', alert: 'alert', dim: 'dim', monoFont: '10px m' };
const out = {};
"""

_HELPERS = ("fmtTime", "fmtDate", "num", "ordinal", "countOf", "agree",
            "metricNum", "absentClass", "closeClause")


def _src(*names: str) -> str:
    return "\n".join(_fn(n) for n in _HELPERS + names) + "\n"


# ---------------------------------------------------------------------------
# trend-chart-unsized-canvas
# ---------------------------------------------------------------------------

def test_every_trend_draw_sizes_the_bitmap_to_its_box_first():
    """First visit: the box had no width when the tab was selected, so the
    chart drew 964 CSS pixels onto the default 300-pixel bitmap and cut the
    newest runs off. Now a draw sizes first, whenever it happens."""
    script = _PRELUDE + r"""
const drawn = [];
const histCtx = { setTransform(...a) { drawn.push(['t', ...a]); }, clearRect() {}, fillRect() {},
  beginPath() {}, moveTo() {}, lineTo() {}, stroke() {}, arc() {}, fill() {}, fillText() {} };
const histCanvas = { clientWidth: 964, clientHeight: 132, width: 300, height: 150 };
const window = { devicePixelRatio: 2 };
""" + _src("syncHistoryBitmap", "drawHistory") + r"""
drawHistory();
out.bitmap = [histCanvas.width, histCanvas.height];
out.transform = drawn[0];
histCanvas.clientWidth = 0;          // hidden again: nothing to size, nothing drawn
out.hidden = syncHistoryBitmap();
console.log(JSON.stringify(out));
"""
    got = _run(script)
    assert got["bitmap"] == [1928, 264], got
    assert got["transform"] == ["t", 2, 0, 0, 2, 0, 0]
    assert got["hidden"] is False
    js = _js()
    assert "new ResizeObserver(() => { drawHistory(); })" in js
    assert "histObserver.observe(histCanvas)" in js
    draw = _fn("drawHistory")
    assert draw.index("syncHistoryBitmap()") < draw.index("fillRect")


# ---------------------------------------------------------------------------
# trend-axis-fabricated-bounds and trend-mixes-run-time-and-world-time
# ---------------------------------------------------------------------------

def _trend_harness(series: str, all_projections: bool = False) -> str:
    return _PRELUDE + r"""
const texts = [];
const lines = [];
const rings = [];
const histCtx = { setTransform() {}, clearRect() {}, fillRect() {}, beginPath() {},
  /* Only the data line, which is stroked in the accent; the baseline is
     the grid colour. */
  moveTo(x, y) { if (this.strokeStyle === 'accent') lines.push(['M', Math.round(x)]); },
  lineTo(x, y) { if (this.strokeStyle === 'accent') lines.push(['L', Math.round(x)]); },
  stroke() {}, arc(x) { rings.push(Math.round(x)); }, fill() {},
  fillText(t) { texts.push(t); } };
const histCanvas = { clientWidth: 416, clientHeight: 132, width: 0, height: 0 };
const window = { devicePixelRatio: 1 };
$('an-hist-all').checked = """ + ("true" if all_projections else "false") + r""";
state.analytics = { projection: { preset: 'all', min_confidence: 'LOW', include_inferred: true },
                    params: { decay_half_life_months: null } };
state.analyticsHistory = { series: """ + series + r""" };
""" + _src("syncHistoryBitmap", "trendKey", "shownTrendKey", "worldTime",
           "trendSeries", "drawHistory")


_P = "{ preset: 'all', min_confidence: 'LOW', include_inferred: true, as_of: %s }"


def test_a_flat_trend_prints_only_what_was_measured():
    """A flat series was padded by 0.5 and the padding printed: a
    constraint of 0.189 read 0.689, and the floor -0.311 was impossible."""
    series = "[" + ", ".join(
        "{ at: '2026-09-%02dT00:00:00Z', value: 0.1889, params: %s, preset: 'all' }"
        % (d, _P % "null") for d in (20, 17)) + "]"
    got = _run(_trend_harness(series) + r"""
drawHistory();
out.texts = texts;
console.log(JSON.stringify(out));
""")
    assert "0.189 in every run shown" in got["texts"], got
    assert not any("0.689" in t or "-0.311" in t for t in got["texts"]), got
    # The x axis says when: the first and last days the runs measured.
    assert "17 Sep 2026" in got["texts"] and "20 Sep 2026" in got["texts"]


def test_a_rising_trend_labels_its_real_ends():
    series = ("[{ at: '2026-09-23T10:00:00Z', value: 50, preset: 'all', params: %s },"
              " { at: '2026-09-23T09:59:00Z', value: 10, preset: 'all', params: %s }]"
              % (_P % "null", _P % "'2026-01-01T00:00:00Z'"))
    got = _run(_trend_harness(series) + r"""
drawHistory();
out.texts = texts;
console.log(JSON.stringify(out));
""")
    # One label, on the left: "lowest" alone in the top right corner sat on
    # the newest, highest point of a rising line (2026-09-24).
    assert "highest 50.000 · lowest 10.000" in got["texts"], got
    assert "1 Jan 2026" in got["texts"] and "23 Sep 2026" in got["texts"]


def test_the_x_axis_is_the_world_time_each_run_measured():
    """Three as-of dates computed a minute apart, in click order March,
    January, May: the line must run January, March, May, spread across the
    months, not bunched on today in click order."""
    series = "[" + ", ".join(
        "{ at: '2026-09-23T10:0%d:00Z', value: %d, preset: 'all', params: %s }"
        % (m, v, _P % ("'%s'" % d)) for m, v, d in (
            (3, 30, "2026-05-01T00:00:00Z"),     # newest first, as the API sends
            (2, 10, "2026-01-01T00:00:00Z"),
            (1, 20, "2026-03-01T00:00:00Z"))) + "]"
    got = _run(_trend_harness(series) + r"""
drawHistory();
out.lines = lines; out.rings = rings;
console.log(JSON.stringify(out));
""")
    xs = [x for _, x in got["lines"]]
    assert xs == sorted(xs), got
    # January at the left edge, May at the right, March in between by date.
    assert xs[0] == 8 and xs[-1] == 408, xs
    assert 150 < xs[1] < 220, xs


def test_runs_under_other_projections_are_never_joined_into_the_line():
    series = ("[{ at: '2026-09-23T10:02:00Z', value: 40, preset: 'all', params: %s },"
              " { at: '2026-09-23T10:01:00Z', value: 90, preset: 'all', params: "
              "{ preset: 'all', min_confidence: 'HIGH', include_inferred: true, as_of: null } },"
              " { at: '2026-09-23T10:00:00Z', value: 30, preset: 'all', params: %s }]"
              % (_P % "null", _P % "null"))
    shown = _run(_trend_harness(series) + r"""
out.rows = trendSeries().rows.length; out.hidden = trendSeries().hidden;
drawHistory(); out.lines = lines.length;
console.log(JSON.stringify(out));
""")
    assert shown["rows"] == 2 and shown["hidden"] == 1, shown
    both = _run(_trend_harness(series, all_projections=True) + r"""
drawHistory();
out.rows = trendSeries().rows.length;
out.joined = lines.length; out.points = rings.length;
console.log(JSON.stringify(out));
""")
    assert both["rows"] == 3
    assert both["joined"] == 2, "the HIGH run was joined into the LOW line"
    assert both["points"] == 3, "the HIGH run is not drawn at all"


def test_every_history_row_names_its_projection():
    got = _run(_PRELUDE + _src("histRow") + r"""
const row = histRow({ at: '2026-09-23T10:00:00Z', value: 1, rank: 1, percentile: 90,
  node_count: 5, preset: 'all', params: { min_confidence: 'MODERATE',
  include_inferred: false, decay_half_life_months: 12, as_of: null } });
out.cell = text(row.children[5]);
console.log(JSON.stringify(out));
""")
    assert got["cell"] == "all  MODERATE and above, inferred out, decay 12 months"


# ---------------------------------------------------------------------------
# analysis-survives-graph-changes and stored-run-currency-and-timestamp
# ---------------------------------------------------------------------------

def _currency_harness() -> str:
    return _PRELUDE + r"""
function anQuery() { const q = new URLSearchParams({ preset: state.proj.preset });
  if (state.proj.as_of) q.set('as_of', state.proj.as_of); return q; }
function syncAnalysisSizeOptions() {}
function renderKeyPlayer() {}
function renderConcor() {}
""" + _const("AN_PROJECTION_CHANGED") + "\n" + _src(
        "analysisFailureText", "blankAnalytics", "analyticsAfterGraphRefresh",
        "checkAnalysisCurrency", "renderAnalyticsFlags", "reviewCoverageText",
        "decayWords") + r"""
const checkAnalysisCurrencySoon = () => { checkAnalysisCurrency(); };
function onScreen(q) {
  state.analytics = { run_id: 'run-1', review_coverage: { ties: 4, proposed: 0,
    accepted: 4, rejected: 0, evidenced: 4, inferred: 0 } };
  state.analyticsQuery = q;
  state.analyticsCurrency = { current: true, checkedAt: '2026-09-23T10:00:00Z' };
}
"""


def test_an_edit_under_the_same_projection_is_checked_not_guessed():
    got = _run(_currency_harness() + r"""
(async () => {
  onScreen('preset=all');
  analyticsAfterGraphRefresh(); await tick();
  // One batched check for every card on screen (F2, 2026-09-24).
  const ask = take('/analytics/currency?preset=all&run_id=run-1');
  ask.resolve({ runs: [{ run_id: 'run-1', current: false }] }); await tick(); await tick();
  out.moved = { flags: text($('an-flags')), status: $('an-status').textContent,
                kept: !!state.analytics };
  analyticsAfterGraphRefresh(); await tick();
  take('/analytics/currency?preset=all&run_id=run-1').resolve(
    { runs: [{ run_id: 'run-1', current: true }] }); await tick(); await tick();
  out.undone = { flags: text($('an-flags')), status: $('an-status').textContent };
  console.log(JSON.stringify(out));
})();
""")
    moved = got["moved"]
    assert moved["kept"], "the numbers were thrown away instead of marked"
    assert "The graph has changed since this run" in moved["flags"], moved
    assert "UTC" in moved["flags"]
    assert "Run the analysis again" in moved["status"]
    assert "has changed" not in got["undone"]["flags"], got["undone"]
    assert "has not changed" in got["undone"]["status"]


def test_a_moved_as_of_clears_the_results_it_no_longer_describes():
    got = _run(_currency_harness() + r"""
onScreen('preset=all');
state.proj.as_of = '2026-01-01T00:00:00Z';
analyticsAfterGraphRefresh();
out.analytics = state.analytics; out.empty = $('an-empty').textContent;
out.results = !$('an-results').hidden; out.asked = calls.length;
console.log(JSON.stringify(out));
""")
    assert got["analytics"] is None and not got["results"], got
    assert "projection changed" in got["empty"]
    assert got["asked"] == 0, "a check was spent on results that were cleared"


def test_every_graph_refresh_reaches_the_pane_and_a_stale_projection_is_dropped_on_entry():
    body = _fn("refreshSociogram")
    assert body.index("renderInspector();") < body.index("analyticsAfterGraphRefresh();")
    latest = _fn("loadLatestAnalysis")
    assert "state.analyticsQuery === anQuery().toString()" in latest
    assert "blankAnalytics(AN_PROJECTION_CHANGED)" in latest
    # A run and a stored read both record the query they were made under.
    assert "state.analyticsQuery = q.toString();" in _fn("runAnalysis")
    assert "state.analyticsQuery = q.toString();" in latest


def test_the_stored_run_status_says_when_how_long_ago_and_whether_it_holds():
    got = _run(_PRELUDE + _src("ageText", "currencyText", "storedRunStatus") + r"""
const at = new Date(Date.now() - 5 * 86400000).toISOString();
out.yes = storedRunStatus({ computed_at: at, current: true });
out.no = storedRunStatus({ computed_at: at, current: false });
out.unknown = storedRunStatus({ computed_at: at, current: null });
console.log(JSON.stringify(out));
""")
    assert got["yes"].startswith("Showing the run of ") and " UTC (5 days ago)." in got["yes"]
    assert "+00:00" not in got["yes"]
    assert re.match(r"Showing the run of \d{4}-\d\d-\d\d \d\d:\d\d UTC ", got["yes"]), got["yes"]
    assert "nothing it was computed from has changed" in got["yes"]
    assert "the graph has changed since" in got["no"]
    assert "Not checked" in got["unknown"]


# ---------------------------------------------------------------------------
# broker-lead-card-overclaims
# ---------------------------------------------------------------------------

def _leads(nodes: str, rule: str = "{ connected_count: 30, median_degree: 7 }") -> str:
    return _PRELUDE + r"""
function actorButton(n) { return el('button', 'an-entity', n.label); }
state.analyticsLeadsAll = {};
""" + _src("renderAnalyticsLeads") + r"""
renderAnalyticsLeads({ node_count: 30, broker_rule: """ + rule + ", nodes: " + nodes + r""" });
out.text = text($('an-leads'));
"""


def test_the_lead_card_says_why_in_each_actors_numbers_and_what_it_cut():
    nodes = "[" + ", ".join(
        "{ id: 'n%d', label: 'a%d', degree: 7, betweenness_rank: %d, constraint_rank: %d, "
        "broker_kind: 'structural_hole', broker_signature: 'Spans a structural hole: x.' }"
        % (i, i, i + 1, 9 - i) for i in range(7)) + ", { id: 'k', label: 'k', degree: 2, " \
        "betweenness_rank: 8, constraint_rank: 20, broker_kind: 'few_ties', " \
        "broker_signature: 'Broker signature: y.' }]"
    got = _run(_leads(nodes) + "console.log(JSON.stringify(out));")
    t = got["text"]
    assert "Few ties, high brokerage" in t and "Spans a structural hole" in t
    assert "a0: 9th least constrained and 1st for brokerage, of 30 entities with ties" in t
    assert "k: degree 2 (median 7), 8th for brokerage of 30 entities with ties" in t
    assert "Showing 5 of 7." in t and "Show all 7" in t
    # The reading is said once per kind, not once per actor.
    assert t.count("Spans a structural hole: x.") == 1


def test_the_lead_card_says_so_when_nobody_qualifies():
    got = _run(_leads("[{ id: 'n', label: 'a', degree: 7, broker_kind: null }]")
               + "console.log(JSON.stringify(out));")
    assert "Nobody here stands out as a broker" in got["text"]


# ---------------------------------------------------------------------------
# communities-anonymous-table-unsortable, rank-percentile-opposite-directions
# ---------------------------------------------------------------------------

def test_the_table_sorts_by_any_heading_and_says_which():
    got = _run(_PRELUDE + _const("AN_SORTS") + "\n" + _src(
        "communityNo", "currentSort", "sortedActors", "sortAnalysisBy",
        "renderSortHeaders") + r"""
function renderAnalyticsTable() {}
const rows = [{ label: 'b', constraint: 0.3, betweenness: 9 },
              { label: 'a', constraint: null, betweenness: 5 },
              { label: 'c', constraint: 0.1, betweenness: 1 }];
out.default = sortedActors(rows).map((n) => n.label);
sortAnalysisBy('constraint');
out.constraint = sortedActors(rows).map((n) => n.label);
renderSortHeaders();
out.aria = ths.map((t) => t.dataset.sort + ':' + t.attrs['aria-sort']);
sortAnalysisBy('constraint');
out.flipped = sortedActors(rows).map((n) => n.label);
sortAnalysisBy('label');
out.label = sortedActors(rows).map((n) => n.label);
console.log(JSON.stringify(out));
""")
    assert got["default"] == ["b", "a", "c"]
    # Least constrained first; an undefined constraint last either way.
    assert got["constraint"] == ["c", "b", "a"]
    assert "constraint:ascending" in got["aria"] and "betweenness:none" in got["aria"]
    assert got["flipped"] == ["b", "c", "a"]
    assert got["label"] == ["a", "b", "c"]


def test_the_headings_are_buttons_and_the_constraint_heading_says_its_direction():
    html = _html()
    head = html[html.index('id="an-table"'):]
    head = head[:head.index("</thead>")]
    assert head.count('class="th-sort"') == 7
    assert 'aria-sort="descending"' in head
    assert "Constraint (low = broker)" in head
    assert 'id="an-community"' in html and 'id="an-community-show"' in html


def test_a_cluster_filter_and_cluster_numbers_that_mean_something():
    got = _run(_PRELUDE + _const("AN_SORTS") + "\n" + _src(
        "communityNo", "communitySize", "currentSort", "sortedActors",
        "renderSortHeaders", "renderCommunityFilter", "rankCell",
        "renderAnalyticsTable") + r"""
function actorButton(n) { return el('button', 'an-entity', n.label); }
function loadMetricHistory() {} function markChartedRow() {} function revealTrend() {}
const a = { node_count: 3, cohesion: { community_sizes: [{ community: 5, size: 2 }, { community: 2, size: 1 }] },
  nodes: [{ id: 'x', label: 'x', community: 5, degree: 1, positive_in_degree: 0, positive_out_degree: 0 },
          { id: 'y', label: 'y', community: 2, degree: 1, positive_in_degree: 0, positive_out_degree: 0 },
          { id: 'z', label: 'z', community: 5, degree: 1, positive_in_degree: 0, positive_out_degree: 0 }] };
state.analytics = a;
state.analyticsCommunityNo = new Map([[5, 1], [2, 2]]);
state.analyticsCommunity = '';
renderAnalyticsTable(a);
out.options = $('an-community').children.map((o) => o.textContent);
out.cells = $('an-body').children.map((tr) => [tr.children[6].textContent, tr.children[6].title]);
state.analyticsCommunity = '5';
renderAnalyticsTable(a);
out.filtered = $('an-body').children.map((tr) => tr.dataset.id);
out.showEnabled = !$('an-community-show').disabled;
out.rowClicks = $('an-body').children.map((tr) => (tr.handlers.click || []).length);
console.log(JSON.stringify(out));
""")
    assert got["options"] == ["All clusters (3 entities)", "Cluster 1 (2 entities)",
                              "Cluster 2 (1 entity)"]
    assert got["cells"][0] == ["1", "Cluster 1: 2 entities"]
    assert got["cells"][1] == ["2", "Cluster 2: 1 entity"]
    assert got["filtered"] == ["x", "z"] and got["showEnabled"]
    # row-drilldown-mouse-only: the row is inert, the name is the control.
    assert got["rowClicks"] == [0, 0]


# ---------------------------------------------------------------------------
# row-drilldown-mouse-only and trend-click-no-visible-response
# ---------------------------------------------------------------------------

def test_the_name_is_a_labelled_button_and_trend_says_where_it_went():
    got = _run(_PRELUDE + r"""
const went = [];
function selectTab(t) { went.push(t); }
function selectNode(id) { went.push(id); }
""" + _src("actorButton", "revealTrend", "markChartedRow") + r"""
const b = actorButton({ id: 'n1', label: 'null_auk' });
b.click();
out.button = [b.tag, b.attrs['aria-label'], b.tabIndex];
out.went = went;
const body = $('an-body');
for (const id of ['n1', 'n2']) {
  const tr = el('tr'); tr.dataset.id = id;
  const t = el('button'); t.setAttribute('aria-pressed', 'false'); tr.appendChild(t);
  body.appendChild(tr);
}
markChartedRow('n2');
out.marked = body.children.map((tr) => [tr.classList.contains('charted'),
  tr.children[0].attrs['aria-pressed']]);
revealTrend();
out.scrolled = $('an-hist-head').scrolled; out.focused = $('an-hist-head').focused;
console.log(JSON.stringify(out));
""")
    assert got["button"] == ["button", "Show null_auk on graph", 0]
    assert got["went"] == ["graph", "n1"]
    assert got["marked"] == [[False, "false"], [True, "true"]]
    assert got["scrolled"]["block"] == "start"
    assert got["focused"] == {"preventScroll": True}
    table = _fn("renderAnalyticsTable")
    handler = table[table.index("trendBtn.addEventListener"):]
    assert "markChartedRow(n.id)" in handler and "revealTrend()" in handler
    assert "tr.addEventListener" not in table
    html = _html()
    assert 'id="an-hist-head" class="h3" tabindex="-1"' in html


def test_the_css_no_longer_makes_the_row_look_clickable_and_fits_the_controls():
    css = APP_CSS.read_text(encoding="utf-8")
    assert "#an-body tr { cursor: pointer; }" not in css
    assert re.search(r"#an-kpp-n \{ min-width: [0-9.]+em; \}", css)
    assert "#an-run { white-space: nowrap; }" in css
    assert "#an-body tr.charted td" in css
    # The stored-run status is a sentence now; it wraps under the controls
    # instead of squeezing the decay select to "(" (found in the capture
    # of the fix, 2026-09-23).
    assert "#pane-analytics .pane-head { flex-wrap: wrap;" in css
    assert "#pane-analytics .pane-head > .field { flex: none; }" in css


# ---------------------------------------------------------------------------
# kpp-blank-on-stored-run and rerun-failure-wipes-results-shared-budget
# ---------------------------------------------------------------------------

def _kpp_harness() -> str:
    return _PRELUDE + r"""
let renders = [];
function renderKeyPlayer() { renders.push(JSON.stringify(state.analyticsKpp)); }
""" + _src("analysisFailureText", "loadKeyPlayer")


def test_the_stored_key_player_is_read_and_a_missing_one_says_so():
    got = _run(_kpp_harness() + r"""
(async () => {
  state.analytics = { run_id: 'r' }; state.analyticsQuery = 'preset=all';
  $('an-kpp-n').value = '3';
  loadKeyPlayer(true); await tick();
  take('/analytics/key-player/latest?preset=all&n=3').reject(new ApiError(404, 'Not found', ''));
  await tick(); await tick();
  out.missing = state.analyticsKpp;
  out.computed = calls.some((c) => c.path.includes('/analytics/key-player?'));
  console.log(JSON.stringify(out));
})();
""")
    assert got["missing"] == {"missing": True, "n": 3}
    assert not got["computed"], "opening the pane spent a metered key-player run"


def test_a_new_removal_set_size_fetches_only_the_key_player():
    got = _run(_kpp_harness() + r"""
(async () => {
  state.analytics = { run_id: 'r' }; state.analyticsQuery = 'preset=all';
  $('an-kpp-n').value = '4';
  loadKeyPlayer(false); await tick();
  take('/analytics/key-player/latest').resolve({ current: false, key_player: { n_remove: 4 } });
  await tick(); await tick();
  take('/analytics/key-player?preset=all&n=4').resolve({ current: true, run_id: 'k4',
    key_player: { n_remove: 4 } });
  await tick(); await tick();
  out.kpp = state.analyticsKpp.run_id; out.suite = state.analytics.run_id;
  out.suiteAsked = calls.some((c) => c.path.includes('/analytics?'));
  out.renders = renders.map((r) => JSON.parse(r));
  console.log(JSON.stringify(out));
})();
""")
    assert got["kpp"] == "k4", "a stale stored set was shown instead of a fresh one"
    assert got["suite"] == "r" and not got["suiteAsked"]
    # The card says it is reading while it reads, and searching only once a
    # search has been asked for (found reviewing the fix, 2026-09-23).
    assert got["renders"][0] == {"pending": True, "reading": True, "n": 4}
    assert got["renders"][1] == {"pending": True, "n": 4}
    assert "$('an-kpp-n').addEventListener('change', onKppSizeChange);" in _js()
    wire = _fn("onKppSizeChange")
    assert "loadKeyPlayer(false)" in wire and "blankAnalytics" not in wire
    assert "state.analyticsKppGen = (state.analyticsKppGen || 0) + 1;" in wire


def _kpp_race_harness() -> str:
    """runAnalysis and loadKeyPlayer together, as the size control drives
    them: the shipped handler, the shipped run, the shipped card loader."""
    return _PRELUDE + r"""
function anQuery() { return new URLSearchParams({ preset: 'all' }); }
function syncAnalysisSizeOptions() {}
function renderKeyPlayer() {}
function loadConcor() {}
const drawnKpp = [];
function renderAnalytics() {
  const k = state.analyticsKpp;
  drawnKpp.push(k ? (k.run_id || (k.pending ? 'pending:' + k.n : 'other')) : null);
}
""" + _const("AN_PROJECTION_CHANGED") + "\n" + "\n".join(
        _fn(n) for n in ("countOf", "agree", "closeClause", "analysisFailureText",
                         "blankAnalytics", "runAnalysis", "loadKeyPlayer",
                         "onKppSizeChange")) + "\n"


def test_a_size_changed_during_a_first_run_asks_for_the_new_size():
    """rerun-failure-wipes-results-shared-budget, found reviewing the fix:
    the size was read when Run was pressed and the handler did nothing
    without results, so the old size's set was drawn under the new control
    and nothing asked again."""
    got = _run(_kpp_race_harness() + r"""
(async () => {
  $('an-kpp-n').value = '3';
  runAnalysis(); await tick();
  $('an-kpp-n').value = '5'; onKppSizeChange(); await tick();
  out.loadedWithoutSuite = calls.some((c) => c.path.includes('/key-player'));
  take('/analytics?').resolve({ run_id: 's1', current: true, computed_at_ms: 5 });
  await tick(); await tick();
  const k = take('/analytics/key-player?');
  out.askedFor = k.path;
  k.resolve({ run_id: 'k5', key_player: { n_remove: 5 } });
  await tick(); await tick();
  out.kpp = state.analyticsKpp.run_id;
  console.log(JSON.stringify(out));
})();
""")
    assert not got["loadedWithoutSuite"]
    assert got["askedFor"].endswith("n=5"), got["askedFor"]
    assert got["kpp"] == "k5"


def test_a_late_run_reply_never_draws_over_the_size_on_screen():
    """C3's guard, restored for the card alone: whichever order the two
    replies land in, the card ends on the set for the size the control
    shows."""
    got = _run(_kpp_race_harness() + r"""
(async () => {
  // The run's reply for the OLD size lands after the new size was asked for.
  $('an-kpp-n').value = '3';
  runAnalysis(); await tick();
  take('/analytics?').resolve({ run_id: 's1', current: true, computed_at_ms: 5 });
  await tick(); await tick();
  const old = take('/analytics/key-player?preset=all&n=3');
  $('an-kpp-n').value = '5'; onKppSizeChange(); await tick();
  const stored = take('/analytics/key-player/latest?preset=all&n=5');
  old.resolve({ run_id: 'k3', key_player: { n_remove: 3 } });
  await tick(); await tick();
  out.lateFirst = state.analyticsKpp;
  out.suiteDrawn = drawnKpp.slice();
  stored.resolve({ run_id: 'k5', current: true, key_player: { n_remove: 5 } });
  await tick(); await tick();
  out.lateFirstFinal = state.analyticsKpp.run_id;

  // The new size answers first and the run's old-size reply lands after it.
  runAnalysis(); await tick();
  take('/analytics?').resolve({ run_id: 's2', current: true, computed_at_ms: 5 });
  await tick(); await tick();
  const old2 = take('/analytics/key-player?preset=all&n=5');
  $('an-kpp-n').value = '4'; onKppSizeChange(); await tick();
  take('/analytics/key-player/latest?preset=all&n=4').resolve(
    { run_id: 'k4', current: true, key_player: { n_remove: 4 } });
  await tick(); await tick();
  old2.resolve({ run_id: 'k5-late', key_player: { n_remove: 5 } });
  await tick(); await tick();
  out.newFirstFinal = state.analyticsKpp.run_id;
  out.suite = state.analytics.run_id;
  console.log(JSON.stringify(out));
})();
""")
    assert got["lateFirst"] == {"pending": True, "reading": True, "n": 5}, (
        "the old size's set was drawn under the new control")
    assert got["suiteDrawn"] == ["pending:5"], "the suite itself must still be drawn"
    assert got["lateFirstFinal"] == "k5"
    assert got["newFirstFinal"] == "k4", "a late Run reply overwrote the newer size's set"
    assert got["suite"] == "s2"


def test_the_key_player_card_names_the_missing_run_and_a_set_that_does_nothing():
    got = _run(_PRELUDE + _src("ageText", "pctOf", "andList", "piecesText",
                               "graphButton", "renderKeyPlayer") + r"""
function showSetOnGraph() {}
$('an-kpp-n').value = '3';
state.analyticsKpp = { missing: true, n: 3 };
renderKeyPlayer();
out.missing = text($('an-kpp'));
state.analyticsKpp = { key_player: { n_remove: 3, fragmentation_before: 0, fragmentation_after: 0,
  fragments_after: [27], removal_set: [{ node_id: 'a', label: 'a' }], top_betweenness_set: [],
  top_betweenness_fragmentation: 0, beats_top_betweenness: false } };
renderKeyPlayer();
out.nothing = text($('an-kpp'));
state.analyticsKpp = { key_player: { n_remove: 2, fragmentation_before: 0, fragmentation_after: 0.61,
  fragments_after: [12, 9, 4, 2], removal_set: [{ node_id: 'a', label: 'a' }, { node_id: 'b', label: 'b' }],
  top_betweenness_set: [{ label: 'c' }, { label: 'd' }], top_betweenness_fragmentation: 0.2,
  beats_top_betweenness: true } };
renderKeyPlayer();
out.found = text($('an-kpp'));
state.analyticsKpp = { pending: true, reading: true, n: 3 };
renderKeyPlayer();
out.reading = text($('an-kpp'));
state.analyticsKpp = { pending: true, n: 3 };
renderKeyPlayer();
out.finding = text($('an-kpp'));
console.log(JSON.stringify(out));
""")
    assert "Not computed for this view yet." in got["missing"]
    assert "Find the 3-entity removal set" in got["missing"]
    assert "would cut nobody off" in got["nothing"]
    assert "Removal set:" not in got["nothing"], "a set that does nothing named people"
    found = got["found"]
    assert "would leave 61% of pairs of entities unable to reach each other" in found
    assert "falls into 4 pieces of 12, 9, 4 and 2 entities" in found
    # F is defined where it is printed (explanations-in-developer-language).
    assert "Fragmentation (F) is that share, as a fraction" in found
    assert "F=" not in found
    # The card that names nobody has given no share to point back at, so
    # it says which share F is (found reviewing the fix, 2026-09-23).
    assert "that share" not in got["nothing"]
    assert ("Fragmentation (F) is the share of pairs of entities unable to reach "
            "each other, as a fraction") in got["nothing"]
    assert "Looking for a stored 3-entity removal set..." == got["reading"]
    assert "Finding the 3-entity removal set..." == got["finding"]


def test_a_failed_rerun_keeps_the_results_and_says_why_in_plain_words():
    script = _PRELUDE + r"""
function anQuery() { return new URLSearchParams({ preset: 'all' }); }
function syncAnalysisSizeOptions() {}
function renderAnalytics() {}
function loadConcor() {}
function fmtTime(v) { return String(v); }
""" + _const("AN_PROJECTION_CHANGED") + "\n" + "\n".join(
        _fn(n) for n in ("countOf", "agree", "closeClause", "analysisFailureText",
                         "blankAnalytics", "runAnalysis")) + r"""
(async () => {
  state.analytics = { run_id: 'earlier' }; state.analyticsQuery = 'preset=all';
  $('an-kpp-n').value = '3';
  runAnalysis(); await tick();
  take('/analytics?').reject(new ApiError(429, 'Too Many Requests',
    "rate limit 'analytics.suite' exceeded; retry in 8s"));
  await tick(); await tick();
  out.kept = state.analytics && state.analytics.run_id;
  out.results = !$('an-results').hidden;
  out.status = $('an-status').textContent;
  out.failed = failed;
  console.log(JSON.stringify(out));
})();
"""
    got = _run(script)
    assert got["kept"] == "earlier", "a throttled re-run threw away the results"
    assert "Analysis is briefly throttled" in got["status"]
    assert "Try again in 8 seconds." in got["status"]
    assert "analytics.suite" not in got["status"]
    assert "The results below are from the earlier run." in got["status"]
    assert got["failed"] == [], "a throttle the status line explains also raised a banner"


# ---------------------------------------------------------------------------
# metrics-hide-review-and-evidence-state and explanations-in-developer-language
# ---------------------------------------------------------------------------

def test_the_coverage_and_the_projection_line_speak_the_readers_words():
    got = _run(_PRELUDE + _src("reviewCoverageText", "decayWords") + r"""
out.none = reviewCoverageText({ ties: 87, proposed: 87, evidenced: 0, rejected: 0 });
out.all = reviewCoverageText({ ties: 3, proposed: 0, evidenced: 1, rejected: 1 });
out.off = decayWords({ decay: { half_life_months: null } });
out.on = decayWords({ decay: { half_life_months: 12, undated_edges: 1 } });
console.log(JSON.stringify(out));
""")
    assert got["none"].startswith("87 of 87 ties behind these numbers are unreviewed proposals, "
                                  "and 0 of 87 rest on an exhibit.")
    assert "leads until those ties are reviewed" in got["none"]
    assert got["all"].startswith("All 3 ties behind these numbers have been reviewed")
    assert "1 tie was rejected in review and still counts here." in got["all"]
    assert got["off"] == "off"
    assert got["on"] == "12 month half-life, 1 tie has no dates recorded and was not decayed"
    render = _fn("renderAnalytics")
    assert "'connected pair', 'connected pairs'" in render
    assert "'dyad'" not in render
    assert "' | decay: ' + decayWords(a)" in render
    flags = _fn("renderAnalyticsFlags")
    assert "reviewCoverageText(rc)" in flags


def test_the_pane_help_and_the_inspector_say_nothing_in_build_team_words():
    html = _html()
    pane = html[html.index('id="pane-analytics"'):html.index('id="pane-evidence"')]
    visible = re.sub(r"<!--.*?-->", " ", pane, flags=re.S)
    visible = re.sub(r"<[^>]+>", " ", visible)
    for word in ("endpoint", "Newman", "Phase 3", "dyad"):
        assert word not in visible, word
    assert 'id="insp-an-brief"' in html
    got = _run(_PRELUDE + _src("communityNo", "renderInspectorAnalysis") + r"""
function selectTab(t) { out.tab = t; }
state.analytics = { node_count: 30, nodes: [{ id: 'n', betweenness_rank: 1, constraint_rank: 4,
  constraint: 0.19, community: 0 }] };
state.analyticsCommunityNo = new Map([[0, 2]]);
renderInspectorAnalysis('n');
out.line = text($('insp-an-brief'));
$('insp-an-brief').children[1].click();
console.log(JSON.stringify(out));
""")
    assert got["line"].startswith("In the analysis run: 1st for brokerage and 4th least "
                                  "constrained of 30, cluster 2.")
    assert "Open the Analysis pane" in got["line"] and got["tab"] == "analytics"
    assert "renderInspectorAnalysis(sel.id);" in _fn("renderInspector")


# ---------------------------------------------------------------------------
# results-dont-reach-the-graph
# ---------------------------------------------------------------------------

def test_a_run_offers_its_metrics_to_the_node_size_control_and_takes_them_back():
    got = _run(_PRELUDE + r"""
const SIZE_METRICS = [['degree', 'Degree']];
const METRIC_LABEL = new Map(SIZE_METRICS);
const sized = [];
function setSizeMetric(k) { state.sizeMetric = k; sized.push(k); }
""" + _const("AN_SIZE_METRICS") + "\n" + _const("AN_SIZE_KEYS") + "\n" + _src(
        "syncAnalysisSizeOptions", "analysisSizeRaw") + r"""
state.analytics = { computed_at: '2026-09-23T14:02:00Z', nodes: [
  { id: 'a', betweenness: 46.3, constraint: 0.15, constraint_percentile: 98, effective_size: 7 },
  { id: 'b', betweenness: 0, constraint: null, constraint_percentile: 2, effective_size: null }] };
syncAnalysisSizeOptions();
out.options = $('sel-metric').children.map((o) => o.textContent);
state.sizeMetric = 'an_looseness';
out.loose = [analysisSizeRaw({ id: 'a' }), analysisSizeRaw({ id: 'b' }), analysisSizeRaw({ id: 'gone' })];
state.analytics = null;
syncAnalysisSizeOptions();
out.after = $('sel-metric').children.map((o) => o.value);
out.sized = sized; out.labels = Array.from(METRIC_LABEL.keys());
console.log(JSON.stringify(out));
""")
    assert got["options"][1:] == [
        "Betweenness (brokerage), from the analysis run of 2026-09-23 14:02 UTC",
        "Low constraint (spans structural holes), from the analysis run of 2026-09-23 14:02 UTC",
        "Effective size (non-redundant contacts), from the analysis run of 2026-09-23 14:02 UTC"]
    assert got["loose"] == [0.98, 0, 0]
    assert got["after"] == ["degree"] and got["sized"] == ["degree"]
    assert got["labels"] == ["degree"]
    assert "if (AN_SIZE_KEYS.has(state.sizeMetric)) return analysisSizeRaw(n);" in _fn("sizeRaw")
    assert "syncAnalysisSizeOptions();" in _fn("blankAnalytics")
    assert "syncAnalysisSizeOptions();" in _fn("renderAnalytics")


def test_a_set_shown_on_the_graph_is_a_focus_the_analyst_can_see_and_leave():
    got = _run(_PRELUDE + r"""
const rendered = [];
function setRendered(n, e, o) { rendered.push([n.map((x) => x.id), e.length, !!(o && o.keepView)]); }
function selectTab(t) { out.tab = t; }
function renderProjectionBar() {}
function pairKey(a, b) { return a < b ? a + '|' + b : b + '|' + a; }
state.graph = { index: new Map() };
state.gnodes = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
state.gedges = [{ src_node_id: 'a', dst_node_id: 'b' }, { src_node_id: 'b', dst_node_id: 'c' }];
""" + _src("showSetOnGraph", "applySetFocus", "focusSets") + r"""
showSetOnGraph({ label: 'the network without the removal set', hide: new Set(['b']), note: 'n' });
out.without = rendered[0];
out.emphasis = focusSets();
showSetOnGraph({ label: 'cluster 1', lit: new Set(['a', 'b']), pairs: new Set(['a|b']) });
const fs = focusSets();
out.lit = [fs.mode, Array.from(fs.nodes), Array.from(fs.pairs)];
out.focus = state.focus.kind;
console.log(JSON.stringify(out));
""")
    assert got["tab"] == "graph"
    assert got["without"] == [["a", "c"], 0, False], got
    assert got["emphasis"] is None, "a hide-only focus dimmed the fragments"
    assert got["lit"] == ["path", ["a", "b"], ["a|b"]]
    assert got["focus"] == "set"
    flag = _fn("renderFocusFlag")
    assert "state.focus.kind === 'set'" in flag and "setFocusSource(state.focus)" in flag
    reapply = _fn("reapplyFocus")
    assert reapply.index("state.focus.kind === 'set'") < reapply.index("state.focus.kind === 'ego'")
    # Hue stays type: nothing in the pane paints a cluster a colour.
    js = _js()
    start = js.index("/* --- results on the sociogram")
    assert "hues" not in js[start:js.index("function renderInspectorAnalysis(")]


def test_a_set_on_the_graph_says_when_its_run_has_left_the_pane_or_gone_stale():
    """Found reviewing results-dont-reach-the-graph (2026-09-23): a set shown
    from the pane stayed "from the Analysis pane" after the pane had
    cleared that run or marked it stale, so the graph kept emphasising
    people on the strength of numbers the pane no longer vouched for."""
    got = _run(_PRELUDE + r"""
function setRendered() {}
function selectTab() {}
function renderProjectionBar() {}
state.gnodes = []; state.gedges = [];
""" + _src("showSetOnGraph", "applySetFocus", "setFocusSource") + r"""
state.analytics = { run_id: 's1' }; state.analyticsCurrency = { current: true };
state.analyticsKpp = { run_id: 'k1', current: true };
showSetOnGraph({ label: 'cluster 1', lit: new Set(['a']) });
out.suiteRun = state.focus.runId;
const cluster = state.focus;
showSetOnGraph({ label: 'the removal set', lit: new Set(['a']), fromKpp: true });
out.kppRun = state.focus.runId;
const removal = state.focus;
out.fresh = [setFocusSource(cluster), setFocusSource(removal)];
state.analyticsCurrency = { current: false };
state.analyticsKpp.current = false;
out.stale = [setFocusSource(cluster), setFocusSource(removal)];
state.analytics = { run_id: 's2' }; state.analyticsCurrency = { current: true };
state.analyticsKpp = { pending: true, n: 4 };
out.replaced = [setFocusSource(cluster), setFocusSource(removal)];
state.analytics = null; state.analyticsKpp = null;
out.cleared = [setFocusSource(cluster), setFocusSource(removal)];
console.log(JSON.stringify(out));
""")
    assert got["suiteRun"] == "s1" and got["kppRun"] == "k1"
    assert got["fresh"] == ["from the Analysis pane"] * 2
    assert got["stale"] == ["from an analysis run the graph has changed since"] * 2
    gone = ["from an analysis run no longer on the Analysis pane"] * 2
    assert got["replaced"] == gone and got["cleared"] == gone
    # And the flag is redrawn when those change: on clearing, on every
    # currency verdict (the flags are redrawn with it), and with the card.
    guard = "if (state.focus && state.focus.kind === 'set') renderFocusFlag();"
    for name in ("blankAnalytics", "renderAnalyticsFlags", "renderKeyPlayer"):
        assert guard in _fn(name), name
    assert "renderAnalyticsFlags(state.analytics);" in _fn("checkAnalysisCurrency")
    card = _fn("renderKeyPlayer")
    assert card.count("fromKpp: true") == 2, "the removal-set buttons must name their run"
