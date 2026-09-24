"""The graph pane around the sociogram, held to the 2026-09-22 review.

Two lenses of that review (ux03 graph navigation, ux04 reading the graph)
found the pane around the canvas working against it: a four-row control
bar that left a 1366x768 sociogram 257px tall; a metrics call on the
Analysis suite's budget that ordinary navigation spent, taking Node size
and the "0% evidenced" headline with it; Space that worked only while the
canvas had focus; pins that could not be undone one at a time and a Clear
pins that wiped the case with no question; a zoom level shown nowhere; the
TRUNCATED and INCOMPLETE warnings buried in a developer-syntax readout; an
empty case told to widen a projection already at its widest; a node size
scale that spent its range on 0 against 1 tie; a density strip flattened
by one import-time spike; victims painted as groups; a legend missing
marks the canvas draws. Each check below is named for what it would have
caught.

Pure, like test_sociogram_canvas: the static assets are read, and where a
number or a branch matters the function is lifted out of app.js and RUN
under node against stubs. No database, no browser. The node runs skip only
where node is absent; the CI runner image ships it.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "noctornal_api" / "http" / "static"
APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"
APP_CSS = STATIC / "app.css"
GRAPHVIEW = ROOT / "src" / "noctornal_api" / "http" / "routers" / "graphview.py"


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """One top-level function, `async` included, up to its closing brace."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    first = js[m.start():js.index("\n", m.start())]
    if first.rstrip().endswith("}") and first.count("{") == first.count("}"):
        return first + "\n"
    return js[m.start():js.index("\n}\n", m.start()) + 3]


def _const(name: str) -> str:
    """A top-level `const NAME = ...;` declaration, whole: one line, or a
    literal closed by `];` or `};` at the start of a line."""
    js = _js()
    m = re.search(rf"^const {re.escape(name)} = ", js, flags=re.M)
    assert m, f"app.js has no top-level const {name}"
    line = js[m.start():js.index("\n", m.start())]
    if re.sub(r"\s*//.*$", "", line).endswith(";"):
        return line + "\n"
    end = re.compile(r"^[\]\}\)];", re.M).search(js, m.start()).end()
    return js[m.start():end] + "\n"


def _between(start: str, end: str, text: str) -> str:
    a = text.index(start)
    return text[a:text.index(end, a)]


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    guess = r"C:\Program Files\nodejs\node.exe"
    return guess if os.path.exists(guess) else None


def _run(script: str) -> dict:
    node = _node()
    if not node:
        pytest.skip("node is not installed here; the static checks still ran")
    res = subprocess.run([node, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


_CLAMP = "function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }\n"


# ---------------------------------------------------------------------------
# ux03 metrics-rate-limit-degrades-view (high)
# ---------------------------------------------------------------------------

def test_the_evidence_headline_never_waits_on_the_metered_call():
    """The "0% evidenced" line came from /graph/metrics, so when that call
    was refused the red line vanished while the analyst was exploring."""
    render = _fn("renderEvidenceCoverage")
    # The projection's rows, or the rows of the focus on the canvas (u7).
    assert "const gnodes = state.gnodes || [], gedges = state.gedges || [];" in render
    assert "coverageLine(nodes, edges," in render
    line = _fn("coverageLine")
    assert "backedCount(nodes, edges)" in line
    assert "row.has_evidence" in _fn("backedCount")
    # The metrics answer may only cross-check the figure in the title
    # (ux07 coverage-vanishes-with-metrics); the figure is the canvas's.
    figure = line[line.index("return { text: 'evidence: '"):]
    assert "fromMetrics" not in figure, (
        "the coverage headline reads the metrics call again")


def test_a_scrub_fetches_the_metrics_once_on_release():
    """A 200 ms debounce fired the metrics call at every pause of a drag."""
    assert "refreshSociogram({ metrics: false })" in _fn("onScrubInput")
    assert "refreshSociogram()" in _fn("onScrubCommit")
    assert "$('tl-range').addEventListener('change', onScrubCommit);" in _js()
    refresh = _fn("refreshSociogram")
    assert "o.metrics === false" in refresh and "holdMetrics(q)" in refresh


def test_a_refusal_carries_its_retry_after_to_the_caller():
    fetch = _fn("_fetch")
    assert "res.headers.get('Retry-After')" in fetch
    assert "err.retryAfter = retryAfter" in fetch


def test_the_metrics_route_has_its_own_meter():
    src = GRAPHVIEW.read_text(encoding="utf-8")
    route = _between('@router.get("/metrics"', "def metrics(", src)
    assert 'rate_limit("graph.metrics")' in route
    assert "analytics.suite" not in route


_METRICS_HARNESS = r"""
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail || ''; }
}
const nodes = {};
function $(id) { if (!nodes[id]) nodes[id] = { id, disabled: false }; return nodes[id]; }
const state = { caseId: 'c1', graphSeq: 1, projTruncated: false,
  gnodes: [{ id: 'a', has_evidence: false }, { id: 'b', has_evidence: false }],
  gedges: [{ id: 'e1', src_node_id: 'a', dst_node_id: 'b', weight: 1, sign: 1,
             confidence: 'LOW', is_inferred: false }],
  metrics: null, metricById: new Map(), ranks: null, rankTotal: 0,
  metricsNote: '', metricsWarned: false, metricsDown: null, metricsRetry: 0,
  metricsCache: new Map(), sizeMetric: 'degree', proj: { preset: 'all' } };
function cpath(p) { return '/cases/' + state.caseId + p; }
function projQuery() { const q = new URLSearchParams(); q.set('preset', state.proj.preset); return q; }
const calls = [];
let reply = null;
function api(path) { calls.push(path); return reply(); }
const failed = [];
function fail(err) { failed.push(err.status); }
function renderProjectionBar() {}
function renderInspector() {}
function draw() {}
const timers = [];
function setTimeout(fn, ms) { timers.push({ fn, ms }); return timers.length; }
function clearTimeout() {}
const SIZE_METRICS = [['degree', 'Degree']];
function roleWords(s) { return s; }   // a 403's wording (ux19-copy)
""" + "\n".join(_fn(f) for f in (
    "subgraphKey", "metricsKey", "metricsUp", "holdMetrics", "refreshMetrics",
    "retryMetrics", "applyMetrics", "computeRanks")) + "\n" \
    + _const("METRICS_CACHE_MAX") + _const("METRICS_RETRY_DEFAULT") + r"""
const M = { nodes: [{ id: 'a', degree: 1 }, { id: 'b', degree: 1 }] };
const out = {};
(async () => {
  // A refused call: waited out, retried, no banner.
  reply = () => { const e = new ApiError(429, 'Too many requests', ''); e.retryAfter = 3;
                  return Promise.reject(e); };
  await refreshMetrics(state.graphSeq, projQuery());
  out.refused = { down: state.metricsDown, disabled: $('sel-metric').disabled,
                  timers: timers.map((t) => t.ms), failed: failed.slice() };
  reply = () => Promise.resolve(M);
  await timers[0].fn();
  out.retried = { down: state.metricsDown, disabled: $('sel-metric').disabled,
                  metrics: !!state.metrics, calls: calls.length };
  // The same projection and the same graph: answered from the cache.
  await refreshMetrics(state.graphSeq, projQuery());
  out.cached = { calls: calls.length, metrics: !!state.metrics };
  // The same projection, a changed graph (an exhibit linked): asked again.
  state.gnodes[0].has_evidence = true;
  await refreshMetrics(state.graphSeq, projQuery());
  out.changed = { calls: calls.length };
  // A drag: never a call; a cached answer is used, else the ties drawn.
  holdMetrics(projQuery());
  out.holdHit = { calls: calls.length, metrics: !!state.metrics };
  state.proj.preset = 'trust';
  holdMetrics(projQuery());
  out.holdMiss = { calls: calls.length, metrics: !!state.metrics, note: state.metricsNote };
  // A refusal with no Retry-After to wait out is reported, once.
  reply = () => Promise.reject(new ApiError(403, 'Forbidden', ''));
  await refreshMetrics(state.graphSeq, projQuery());
  await refreshMetrics(state.graphSeq, projQuery());
  out.forbidden = { failed: failed.slice(), timers: timers.length };
  console.log(JSON.stringify(out));
})();
"""


def test_a_refused_metrics_call_retries_by_itself_and_navigation_is_cached():
    """ux03 metrics-rate-limit-degrades-view: nothing re-fetched when the
    budget refilled, so the degraded view stood until another control was
    touched; and every control change spent a call."""
    got = _run(_METRICS_HARNESS)
    assert got["refused"]["down"] == {"why": "the rate limit", "retryIn": 3}, got
    assert got["refused"]["timers"] == [3000], "the retry does not wait out Retry-After"
    assert got["refused"]["failed"] == [], "a refusal being retried raised a banner"
    assert got["retried"] == {"down": None, "disabled": False, "metrics": True,
                              "calls": 2}, got["retried"]
    assert got["cached"] == {"calls": 2, "metrics": True}, "a revisited projection asked again"
    assert got["changed"] == {"calls": 3}, "a changed graph was served a cached answer"
    assert got["holdHit"] == {"calls": 3, "metrics": True}
    assert got["holdMiss"]["calls"] == 3 and got["holdMiss"]["metrics"] is False
    assert "let go" in got["holdMiss"]["note"]
    assert got["forbidden"] == {"failed": [403], "timers": 1}, got["forbidden"]


# ---------------------------------------------------------------------------
# ux03 space-needs-canvas-focus
# ---------------------------------------------------------------------------

def test_space_is_answered_for_the_whole_graph_tab():
    init = _fn("initCanvas")
    assert "document.addEventListener('keydown', onSpaceDown);" in init
    assert "document.addEventListener('keyup'" in init
    keys = _fn("onCanvasKey")
    assert "e.key === ' '" not in keys, "Space is back on the canvas's own keydown"
    wire = _fn("wireCanvasControls")
    assert "canvas.focus({ preventScroll: true })" in wire, (
        "a pointer on a projection control keeps the focus again")
    assert "e.detail > 0" in wire, "a key press on a button hands focus away"
    html = _html()
    keys_strip = html[html.index('<p class="canvas-keys">'):]
    assert '<span class="kbd">hold space</span> hide inferred' in keys_strip
    sheet = html[html.index('<h3 class="h-xs">Sociogram</h3>'):]
    space = " ".join(sheet[:sheet.index("</dl>")].split())
    assert "anywhere on the graph tab, the timeline and the inspector included" in space
    # The sheet no longer promises a peek after ANY click: an inspector
    # button just used keeps its own Space.
    assert "an inspector button you just used" in space
    # While held, the canvas says what it hid.
    assert "hidden: release Space" in _fn("noteHold")


def test_space_peeks_except_where_space_already_means_something():
    script = r"""
const canvas = { tagName: 'CANVAS' };
const document = { body: { tagName: 'BODY' }, documentElement: { tagName: 'HTML' } };
const state = { tab: 'graph', graph: {} };
function signedIn() { return true; }
function mk(tag, o) {
  o = o || {};
  return { tagName: tag, type: o.type || '', isContentEditable: !!o.editable,
    closest(sel) {
      // The graph pane and the inspector beside it; anything else is outside.
      if (sel.indexOf('#pane-graph') >= 0) return o.outside ? null : {};
      if (sel.indexOf('dialog') >= 0) return o.dialog ? {} : null;
      return null;
    },
    getAttribute(n) { return n === 'role' ? (o.role || null) : null; } };
}
""" + _fn("spacePeeks") + r"""
const out = {
  body: spacePeeks(document.body), canvas: spacePeeks(canvas),
  paneDiv: spacePeeks(mk('DIV')), legendSpan: spacePeeks(mk('SPAN')),
  checkbox: spacePeeks(mk('INPUT', { type: 'checkbox' })),
  text: spacePeeks(mk('INPUT', { type: 'text' })), select: spacePeeks(mk('SELECT')),
  // The timeline slider has no use for Space, so it peeks from there.
  slider: spacePeeks(mk('INPUT', { type: 'range' })),
  sliderInDialog: spacePeeks(mk('INPUT', { type: 'range', dialog: true })),
  button: spacePeeks(mk('BUTTON')), roleButton: spacePeeks(mk('TR', { role: 'button' })),
  editable: spacePeeks(mk('DIV', { editable: true })),
  outsidePane: spacePeeks(mk('DIV', { outside: true })),
  inDialog: spacePeeks(mk('DIV', { dialog: true })),
};
state.tab = 'triage';
out.otherTab = spacePeeks(document.body);
state.tab = 'graph'; state.graph = null;
out.noGraph = spacePeeks(document.body);
console.log(JSON.stringify(out));
"""
    got = _run(script)
    assert got == {
        "body": True, "canvas": True, "paneDiv": True, "legendSpan": True,
        "checkbox": False, "text": False, "select": False,
        "slider": True, "sliderInDialog": False,
        "button": False, "roleButton": False,
        "editable": False, "outsidePane": False, "inDialog": False,
        "otherTab": False, "noGraph": False,
    }, got
    # The inspector is on screen with the graph, so it is inside the zone.
    assert "t.closest('#pane-graph, #inspector')" in _fn("spacePeeks")


def test_a_click_on_the_timeline_hands_space_back_to_the_canvas():
    """Fix round: a mouse click on "as-of: now" kept the focus, so Space
    pressed it again, and a mouse drag of the slider left Space dead. Run
    under node: every zone's pointer click on a button hands focus back to
    the canvas, the slider keeps its own focus, and a key press never
    moves it."""
    script = r"""
let focused = 0;
const canvas = { focus() { focused += 1; } };
const state = { tab: 'graph', selection: null };
function mkZone(name) {
  const on = {};
  return { name, on, addEventListener(t, fn) { (on[t] = on[t] || []).push(fn); } };
}
const zones = { '.proj-bar': mkZone('bar'), scrubber: mkZone('scrubber'),
                tools1: mkZone('layout'), tools2: mkZone('zoom') };
const document = {
  querySelector(s) { return zones[s] || null; },
  querySelectorAll(s) { return s === '.canvas-tools' ? [zones.tools1, zones.tools2] : []; },
};
const window = { addEventListener() {} };
const buttons = {};
function $(id) {
  if (zones[id]) return zones[id];
  if (!buttons[id]) buttons[id] = { id, addEventListener() {}, getAttribute() { return 'false'; },
                                    setAttribute() {} };
  return buttons[id];
}
function zoomAt() {} function togglePin() {} function show() {}
function guardLayout() {}
""" + _fn("wireCanvasControls") + r"""
wireCanvasControls();
function fire(zone, type, e) { for (const fn of zone.on[type] || []) fn(e); }
const button = { tagName: 'BUTTON', type: 'button', closest() { return this; } };
const slider = { tagName: 'INPUT', type: 'range', closest() { return this; } };
const out = {};
// A mouse click on "as-of: now".
fire(zones.scrubber, 'pointerdown', {});
fire(zones.scrubber, 'click', { detail: 1, target: button });
out.asOfNow = focused;
// A mouse drag of the slider: change, then click. It keeps its focus.
fire(zones.scrubber, 'pointerdown', {});
fire(zones.scrubber, 'change', { target: slider });
fire(zones.scrubber, 'click', { detail: 1, target: slider });
out.sliderDrag = focused;
// A key press on the button (Space or Enter): the focus stays put.
fire(zones.scrubber, 'keydown', {});
fire(zones.scrubber, 'click', { detail: 0, target: button });
out.keyPress = focused;
// And the projection bar and the canvas tools still hand it back.
for (const z of [zones['.proj-bar'], zones.tools1, zones.tools2]) {
  fire(z, 'pointerdown', {});
  fire(z, 'click', { detail: 1, target: button });
}
out.otherZones = focused;
console.log(JSON.stringify(out));
"""
    got = _run(script)
    assert got == {"asOfNow": 1, "sliderDrag": 1, "keyPress": 1, "otherZones": 4}, got


# ---------------------------------------------------------------------------
# ux03 pin-layout-work-lost
# ---------------------------------------------------------------------------

def test_one_pin_can_be_undone_and_the_hint_says_a_drag_pins():
    assert "togglePin(ids[cur])" in _fn("onCanvasKey")
    assert "togglePin(sel.id)" in _fn("wireCanvasControls")
    toggle = _fn("togglePin")
    assert "n.pinned = !n.pinned" in toggle and "state.layoutDirty.add(n.id)" in toggle
    html = _html()
    canvas_wrap = _between('<div class="canvas-wrap">', "<!-- THE SIGNATURE ELEMENT", html)
    assert 'id="btn-pin"' in canvas_wrap
    assert '<span class="kbd">drag a node</span> move and pin' in html
    assert '<span class="kbd">U</span> pin or unpin' in html


def test_unsaved_placements_are_marked_and_never_lost_silently():
    init = _fn("initCanvas")
    pointer_move = _between("canvas.addEventListener('pointermove'", "canvas.addEventListener('pointerup'", init)
    assert "state.layoutDirty.add(g.drag.id)" in pointer_move
    sync = _fn("syncCanvasControls")
    assert "classList.toggle('dirty'" in sync
    assert "window.addEventListener('beforeunload', guardLayout);" in _fn("wireCanvasControls")
    guard = _fn("guardLayout")
    assert "state.layoutDirty.size" in guard and "state.layoutCarry" in guard
    # A case switch deals with them, and does it BEFORE the canvas reset
    # drops the graph. (CRLF-agnostic: the tree may be checked out either way.)
    js = _js().replace("\r\n", "\n")
    leave = js.index("|| state.layoutCarry)) {\n    leaveLayout();")
    reset = js.index("onCaseSwitch(() => {\n  stopWorkerLayout();")
    assert leave < reset, "the leave-save registers after the reset that drops the graph"
    assert "'/cases/' + caseId + '/graph/layout'" in _fn("saveLayoutOnLeave")
    assert "state.layoutCarry" in _fn("loadLayout")
    assert "state.layoutDirty = new Set()" in _fn("saveLayout")


_POINTER_HARNESS = r"""
const handlers = {};
const canvas = { clientWidth: 800, clientHeight: 600, parentElement: {},
  addEventListener(t, fn) { handlers[t] = fn; }, focus() {},
  setPointerCapture() {}, releasePointerCapture() {} };
const document = { addEventListener() {} };
const window = { addEventListener() {} };
const reduceMotion = true;
const node = { id: 'n1', x: 100, y: 100, vx: 0, vy: 0, pinned: false };
const state = { graph: { nodes: [node], drag: null, alpha: 0, raf: 0 },
                layoutDirty: new Set(), view: { tx: 0, ty: 0, scale: 1 },
                hoverId: null, needFit: true, selection: null, pathAnchor: null };
function canvasPoint(e) { return { x: e.x, y: e.y }; }
function toWorld(x, y) { return { x, y }; }
function nodeAt(p) { return Math.hypot(p.x - node.x, p.y - node.y) < 12 ? node : null; }
function edgeAt() { return null; }
function yieldLayoutToDrag() {} function requestAnimationFrame() { return 1; } function frame() {}
function draw() {} function takeView() {} function syncLayoutFromSim() {}
function pickOnCanvas(fn) { fn(); } let picked = 0; function selectNode() { picked += 1; }
function renderFocusFlag() {} function enterPath() {} function renderInspector() {}
function enterEgo() {} function zoomAt() {} function onCanvasKey() {} function onSpaceDown() {}
function wireCanvasControls() {} function resizeGraph() {} function resizeDensity() {}
function watchCanvasChrome() {}            // the chrome's plates (c12)
function caseReadOnly() { return false; }   // an open case
""" + "{INIT}" + r"""
initCanvas();
function gesture(dx) {
  handlers.pointerdown({ button: 0, x: 100, y: 100, pointerId: 1 });
  handlers.pointermove({ x: 100 + dx, y: 100, pointerId: 1 });
  handlers.pointerup({ x: 100 + dx, y: 100, pointerId: 1, shiftKey: false });
  return { pinned: node.pinned, dirty: Array.from(state.layoutDirty), x: node.x };
}
const out = {};
out.wobble = gesture(2);        // a click with a 2px wobble
out.picked = picked;
node.x = 100;
out.drag = gesture(20);         // a real drag
console.log(JSON.stringify(out));
"""


def test_a_click_with_a_wobble_neither_moves_nor_silently_pins():
    """Fix round: pointermove pinned the node on ANY movement, pointerup
    marked it unsaved only past 3px, so a click with a 2px wobble pinned the
    entity with no dot on Save layout, and the next save stored it."""
    got = _run(_POINTER_HARNESS.replace("{INIT}", _fn("initCanvas")))
    assert got["wobble"] == {"pinned": False, "dirty": [], "x": 100}, got["wobble"]
    assert got["picked"] == 1, "the wobbly click no longer selects"
    assert got["drag"] == {"pinned": True, "dirty": ["n1"], "x": 120}, got["drag"]


_LEAVE_HARNESS = r"""
const state = { caseId: 'A', caseRec: { code: 'OP-A' }, graph: {}, layoutCarry: null,
                layoutDirty: new Set(), layout: new Map() };
function caseCodeNow() { return state.caseRec ? state.caseRec.code : state.caseId; }
function syncLayoutFromSim() {}
function countOf(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
function agree(n, one, many) { return n === 1 ? one : many; }
function failureReason() { return 'offline'; }
const puts = [], banners = [];
let rows = [];                   // what GET /graph/layout answers
function api(path, o) {
  if (!o) return Promise.resolve(rows);
  puts.push({ path, n: o.json.positions.length });
  return Promise.resolve({});
}
function banner(title, text) { banners.push(title + ': ' + text); }
function cpath(p) { return '/cases/' + state.caseId + p; }
const seq = 0;
function caseToken() { return seq; }
function caseChanged(t) { return t !== seq; }
function fail() {}
const CASE_STATES_SHUT = new Set(['CLOSED', 'ARCHIVED', 'PURGED']);
""" + "{FNS}" + r"""
const tick = () => new Promise((r) => setTimeout(r, 0));
function placed() {
  state.layout = new Map([['n1', { node_id: 'n1', x: 5, y: 6, is_pinned: true }],
                          ['n2', { node_id: 'n2', x: 1, y: 2, is_pinned: false }]]);
  state.layoutDirty = new Set(['n1']);
  state.graph = {};
}
// The reset as openCase(state.caseId) runs it: the same case, read again.
function resetThen(next) {
  if (state.caseId && ((state.layoutDirty.size && state.graph) || state.layoutCarry)) {
    leaveLayout();
  }
  state.layoutDirty = new Set();
  state.graph = null;
  state.caseId = next;           // openCase and showCaseList set it straight after
  state.caseRec = null;
  state.layout = new Map();
}
(async () => {
  const out = {};
  placed();
  resetThen('A');
  await tick();
  out.sameCase = { puts: puts.length, banners: banners.length,
                   carry: state.layoutCarry && state.layoutCarry.positions.map((p) => p.node_id) };
  // loadLayout lands: the placement is back over it, still unsaved.
  rows = [{ node_id: 'n1', x: 0, y: 0, is_pinned: false }];
  await loadLayout();
  out.afterLoad = { n1: state.layout.get('n1'), dirty: Array.from(state.layoutDirty),
                    carry: state.layoutCarry };
  // A real switch: saved to the case it was made in, with a message.
  state.caseRec = { code: 'OP-A' }; state.graph = {};
  resetThen('B');
  await tick(); await tick();
  out.switched = { puts: puts.slice(), banner: banners[0] || null };
  // Re-read, then away before the layout ever loaded: the carry is saved.
  state.caseId = 'A'; state.caseRec = { code: 'OP-A' };
  placed();
  resetThen('A');
  await tick();
  resetThen(null);               // the case list
  await tick(); await tick();
  out.carriedAway = { puts: puts.slice(1), carry: state.layoutCarry };
  // A read-only case refuses a layout write: nothing is stored or carried.
  puts.length = 0; banners.length = 0;
  state.caseId = 'C'; state.caseRec = { code: 'OP-C', status: 'CLOSED', read_only: true };
  placed();
  resetThen('B');
  await tick(); await tick();
  out.readOnly = { puts: puts.length, banners: banners.length, carry: state.layoutCarry };
  console.log(JSON.stringify(out));
})();
"""


def test_reading_the_same_case_again_keeps_placements_unsaved_and_says_nothing():
    """Fix round: a title edit or a status change re-opens the SAME case,
    and the leave-save ran anyway: a banner said the placements were
    "saved as you left" when the analyst had not left, and its PUT raced
    the layout read of the same case."""
    fns = "\n".join(_fn(f) for f in ("leaveLayout", "loadLayout", "saveLayoutOnLeave",
                                     "layoutPositions", "caseReadOnly"))
    got = _run(_LEAVE_HARNESS.replace("{FNS}", fns))
    assert got["readOnly"] == {"puts": 0, "banners": 0, "carry": None}, got["readOnly"]
    assert got["sameCase"] == {"puts": 0, "banners": 0, "carry": ["n1"]}, got["sameCase"]
    assert got["afterLoad"]["n1"] == {"node_id": "n1", "x": 5, "y": 6, "is_pinned": True}
    assert got["afterLoad"]["dirty"] == ["n1"] and got["afterLoad"]["carry"] is None
    assert got["switched"]["puts"] == [{"path": "/cases/A/graph/layout", "n": 1}], got["switched"]
    assert "saved as you left" in got["switched"]["banner"]
    assert got["carriedAway"] == {"puts": [{"path": "/cases/A/graph/layout", "n": 1}],
                                  "carry": None}, got["carriedAway"]


def test_clear_pins_asks_with_a_count_stores_only_its_own_pins_and_can_undo():
    clear = _fn("clearPins")
    assert "window.confirm(" in clear and "countOf(ids.length, 'entity', 'entities')" in clear
    assert "layoutPositions()" not in clear, (
        "Clear pins writes the whole stored layout again, not just the pins it cleared")
    assert "before.map(" in clear and "'Undo'" in clear and "restorePins(" in clear
    assert "is_pinned: true" in _fn("clearPins")
    restore = _fn("restorePins")
    assert "'/cases/' + caseId + '/graph/layout'" in restore
    assert "caseChanged(token)" in restore
    # The palette's entry no longer promises to unpin every node silently.
    assert "hint: 'unpin every node'" not in _js()


def test_clear_pins_is_scoped_to_the_focus():
    script = r"""
const state = { focus: null, layout: new Map(), graph: null };
""" + _fn("pinScopeIds") + r"""
const n = (id, pinned) => ({ id, pinned });
const drawn = [n('a', true), n('b', false), n('c', true)];
state.graph = { nodes: drawn, index: new Map(drawn.map((x) => [x.id, x])) };
state.layout.set('a', { is_pinned: true });
state.layout.set('b', { is_pinned: true });   // drawn unpinned: the canvas wins
state.layout.set('z', { is_pinned: true });   // pinned, not drawn
state.layout.set('y', { is_pinned: false });
const out = { whole: pinScopeIds().sort() };
state.focus = { kind: 'ego', id: 'a' };
out.focus = pinScopeIds().sort();
console.log(JSON.stringify(out));
"""
    got = _run(script)
    assert got == {"whole": ["a", "c", "z"], "focus": ["a", "c"]}, got


# ---------------------------------------------------------------------------
# ux03 control-bar-squeezes-canvas, ux04 canvas-squeezed-on-laptop
# ---------------------------------------------------------------------------

def test_the_projection_bar_holds_controls_and_the_canvas_holds_its_own():
    html = _html()
    bar = _between('<div class="proj-bar">', '<div class="canvas-wrap">', html)
    for button in ("btn-fit", "btn-relayout", "btn-save-layout", "btn-clear-pins",
                   "btn-refresh"):
        assert f'id="{button}"' not in bar, f"{button} is back in the projection bar"
        wrap = _between('<div class="canvas-wrap">', "<!-- THE SIGNATURE ELEMENT", html)
        assert f'id="{button}"' in wrap, f"{button} is not on the canvas"
    # The preset's gloss is behind a disclosure, and the metric note that
    # restated the chosen metric is gone: a size that is NOT the chosen
    # metric is said on the canvas, where it costs no height.
    assert '<p id="preset-desc" class="proj-desc" hidden>' in bar
    assert 'aria-controls="preset-desc"' in bar and 'aria-expanded="false"' in bar
    assert 'id="metric-note"' not in _html()
    assert "state.metricsNote = 'size = '" not in _js(), (
        "the note restates the chosen metric again")
    status = _fn("renderCanvasStatus")
    assert "metrics unavailable (" in status and "until you let go" in status
    # Short option labels: the glosses live in METRIC_GLOSS.
    sizes = _const("SIZE_METRICS")
    assert "(" not in sizes.split("[", 1)[1], "a Node size option carries its gloss again"
    assert "and above" not in _const("MIN_CONF_OPTIONS")


def test_the_scrubber_is_two_rows():
    html = _html()
    scrub = _between('<div id="scrubber" class="scrubber">', '<div class="graph-bar">', html)
    assert 'class="tl-labels"' not in scrub
    head = _between('<div class="tl-head">', "</div>", scrub)
    assert 'id="tl-note"' in head, "the density note is on a row of its own again"
    track = _between('<div class="tl-track">', "</div>", scrub)
    for part in ("tl-min", "tl-density", "tl-range", "tl-max"):
        assert f'id="{part}"' in track
    css = APP_CSS.read_text(encoding="utf-8")
    assert re.search(r"\.tl-track \{[^}]*display: grid", css)


# ---------------------------------------------------------------------------
# ux03 zoom-state-invisible
# ---------------------------------------------------------------------------

def test_the_zoom_level_and_its_controls_are_on_the_canvas():
    html = _html()
    wrap = _between('<div class="canvas-wrap">', "<!-- THE SIGNATURE ELEMENT", html)
    for part in ("zoom-level", "btn-zoom-in", "btn-zoom-out", "btn-fit", "legend-names"):
        assert f'id="{part}"' in wrap, f"{part} is not on the canvas"
    assert "Math.round(state.view.scale * 100) + '%'" in _fn("noteZoom")
    assert "noteZoom();" in _fn("noteView")
    wire = _fn("wireCanvasControls")
    assert "$('btn-zoom-in')" in wire and "$('btn-zoom-out')" in wire
    keys = html[html.index('<p class="canvas-keys">'):]
    keys = keys[:keys.index("</p>")]
    for cap in ('<span class="kbd">+</span>', '<span class="kbd">&minus;</span>',
                '<span class="kbd">0</span>', '<span class="kbd">&larr; &rarr;</span>',
                '<span class="kbd">Enter</span>', '<span class="kbd">P</span>'):
        assert cap in keys, f"the hint strip omits {cap}"


# ---------------------------------------------------------------------------
# ux03 readout-buries-warnings
# ---------------------------------------------------------------------------

def test_the_warnings_are_on_the_canvas_and_the_readout_is_words():
    readout = _fn("renderReadout")
    for dev in ("'preset='", "'include_inferred='", "'min_confidence='", "TRUNCATED",
                "INCOMPLETE", "edge_types="):
        assert dev not in readout, f"the readout still carries {dev}"
    assert "'Showing '" in readout
    status = _fn("renderCanvasStatus")
    for warning in ("TRUNCATED at", "INCOMPLETE:", "metrics unavailable", "show up to "):
        assert warning in status
    html = _html()
    wrap = _between('<div class="canvas-wrap">', "<!-- THE SIGNATURE ELEMENT", html)
    assert 'id="graph-warnings"' in wrap and 'id="evidence-coverage"' in wrap
    assert "renderCanvasStatus();" in _fn("renderProjectionBar")


def test_the_readout_counts_inferred_ties_in_metrics_only_when_there_are_some():
    """Fix round: an empty case, a refused metrics call or a timeline drag
    has no metrics, and the readout said "counted in the metrics" anyway."""
    script = r"""
const box = { kids: [], appendChild(n) { this.kids.push(n); } };
function $() { return box; }
function clear(b) { b.kids = []; }
function el(tag, cls, text) { return { tag, text }; }
function countOf(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
function fmtTime(t) { return t; }
function num(v) { return String(v); }
function viewWords() { return 'View'; }          // the title (ux19-copy)
function viewParameters() { return 'preset=all'; }
const CASE_LIST_PAGE = 1000;
const state = { projMeta: { include_inferred: true }, proj: { include_inferred: true,
                preset: 'all', min_confidence: 'LOW' }, nodes: [], graph: { nodes: [], links: [] },
                metrics: null };
""" + _fn("renderReadout") + r"""
const line = () => { renderReadout(); return box.kids[0].text; };
const out = { empty: line() };
state.metrics = { node_count: 0, density: 0 };
out.emptyWithMetrics = line();
state.graph = { nodes: [{}, {}], links: [{}] }; state.nodes = [{}, {}];
state.metrics = null;
out.noMetrics = line();
state.metrics = { node_count: 2, density: 1 };
out.withMetrics = line();
console.log(JSON.stringify(out));
"""
    got = _run(script)
    for key in ("empty", "emptyWithMetrics", "noMetrics"):
        assert "counted in the metrics" not in got[key], (key, got[key])
        assert "inferred ties included" in got[key]
    assert "inferred ties included, and counted in the metrics" in got["withMetrics"]


def test_the_canvas_chrome_is_two_wrapping_rows_that_cannot_overlap():
    """Fix round: four absolutely placed boxes held apart by guessed
    max-widths. At 1024 wide the canvas note covered the zoom cluster's
    names note, and disabled tools let the graph show through their words."""
    html = _html()
    wrap = _between('<div class="canvas-wrap">', "<!-- THE SIGNATURE ELEMENT", html)
    head = _between('<div class="canvas-head">', '<div class="canvas-foot">', wrap)
    assert 'id="graph-status"' in head and "canvas-tools-layout" in head
    foot = wrap[wrap.index('<div class="canvas-foot">'):]
    assert foot.index('id="graph-note"') < foot.index("canvas-tools-zoom"), (
        "the note must come first in the foot, so the zoom cluster sits right")
    assert 'id="legend-names"' in foot
    css = APP_CSS.read_text(encoding="utf-8")
    rows = re.search(r"\.canvas-head, \.canvas-foot \{([^}]*)\}", css)
    assert rows and "display: flex" in rows.group(1) and "flex-wrap: wrap" in rows.group(1)
    for rule in (".canvas-note {", ".canvas-status {", ".canvas-tools {"):
        body = css[css.index(rule):css.index("}", css.index(rule))]
        assert "position: absolute" not in body, f"{rule} is an absolute box again"
        assert "calc(100% -" not in body, f"{rule} is held apart by a guessed width again"
    disabled = re.search(r"\.canvas-tools \.btn\[disabled\],\s*\.canvas-tools \.btn\[disabled\]:hover \{([^}]*)\}", css)
    assert disabled and "opacity: 1" in disabled.group(1)
    assert "background: var(--surface-1)" in disabled.group(1)
    assert ".canvas-tools .btn:disabled { opacity" not in css


# ---------------------------------------------------------------------------
# ux03 empty-case-says-widen
# ---------------------------------------------------------------------------

_EMPTY_HARNESS = r"""
const els = {};
function $(id) { if (!els[id]) els[id] = { id, hidden: true, textContent: '', onclick: null,
                                            click() { out.clicked = id; } }; return els[id]; }
function show(n, on) { n.hidden = !on; }
function countOf(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
function agree(n, one, many) { return n === 1 ? one : many; }
function fmtTime(t) { return t + ' UTC'; }
const CASE_STATES_SHUT = new Set(['CLOSED', 'ARCHIVED', 'PURGED']);
function selectTab() {}
function resetAsOf() {}
function reloadAll() {}
const state = { caseId: 'c', graph: { nodes: [] }, nodes: [], proj: { as_of: null },
                caseRec: { status: 'ACTIVE' },
                withheld: { incomplete: false, mode: 'PRESENCE' } };
const out = {};
$('btn-case-status').hidden = false;
""" + _fn("renderGraphEmpty") + r"""
function snap() {
  renderGraphEmpty();
  return { shown: !$('graph-empty').hidden, text: $('graph-empty-text').textContent,
           act: $('graph-empty-act').hidden ? null : $('graph-empty-act').textContent };
}
out.newActive = snap();
state.caseRec.status = 'DRAFT'; out.newDraft = snap();
state.caseRec.status = 'CLOSED'; out.newClosed = snap();
state.caseRec.status = 'ACTIVE';
// Every entity above the reader's clearance: the list is empty too.
state.withheld = { incomplete: true, mode: 'COUNT', nodes: 5, edges: 7 };
out.aboveCount = snap();
state.withheld = { incomplete: true, mode: 'PRESENCE' };
out.abovePresence = snap();
// A case that discloses nothing: no claim either way.
state.withheld = null;
out.undisclosed = snap();
state.caseRec.status = 'CLOSED'; out.undisclosedClosed = snap();
state.caseRec.status = 'ACTIVE';
state.withheld = { incomplete: false, mode: 'PRESENCE' };
state.nodes = [{}, {}, {}];
state.proj.as_of = '2025-01-01';
out.past = snap();
state.proj.as_of = null;
out.filtered = snap();
state.graph = { nodes: [{}] };
out.drawn = snap();
state.graph = null;
out.loading = snap();
console.log(JSON.stringify(out));
"""


def test_an_empty_canvas_says_which_thing_is_empty():
    got = _run(_EMPTY_HARNESS)
    assert got["newActive"] == {"shown": True, "text": "This case has no entities yet.",
                                "act": "Add the first entity"}, got["newActive"]
    assert got["newDraft"]["act"] == "Change status…" and "DRAFT" in got["newDraft"]["text"]
    assert got["newClosed"]["act"] is None and "CLOSED" in got["newClosed"]["text"]
    # Fix round: every entity above the reader's clearance is not an empty
    # case, and there is nothing for the reader to press.
    assert got["aboveCount"] == {
        "shown": True, "act": None,
        "text": "5 entities in this case are above your clearance, and none is "
                "within it, so nothing is drawn."}, got["aboveCount"]
    assert got["abovePresence"]["act"] is None
    assert "above your clearance" in got["abovePresence"]["text"]
    for key in ("aboveCount", "abovePresence", "undisclosed", "undisclosedClosed"):
        assert "has no entities" not in got[key]["text"], (key, got[key])
    assert got["undisclosed"] == {"shown": True, "act": "Add the first entity",
                                  "text": "There are no entities to show in this case yet."}
    assert "CLOSED" in got["undisclosedClosed"]["text"]
    assert got["past"]["act"] == "as-of: now" and "3 entities" in got["past"]["text"]
    assert got["filtered"]["act"] == "Reload graph"
    for key in ("newActive", "newDraft", "newClosed", "past", "filtered"):
        assert "Widen" not in got[key]["text"], "the empty state sends the analyst to widen again"
    assert got["drawn"]["shown"] is False and got["loading"]["shown"] is False
    sync = _fn("syncCanvasControls")
    for button in ("btn-fit", "btn-relayout", "btn-save-layout"):
        assert f"setDisabled('{button}', none)" in sync


# ---------------------------------------------------------------------------
# ux04 size-scale-flattens-hubs
# ---------------------------------------------------------------------------

def test_node_area_is_in_proportion_to_the_metric_from_zero():
    """log1p then sqrt, normalised to the smallest value on screen, put
    NIGHTJAR's 18-tie crew at 16px beside a 5-tie persona at 13.6px, and
    drew KESTREL's 2-tie amber_gannet4 as a bare dot."""
    script = _CLAMP + "\n".join(_const(c) for c in ("NODE_R_MIN", "NODE_R_MAX", "NODE_R_FLAT")) \
        + "\n" + "\n".join(_fn(f) for f in ("sizeRaw", "sizeDomain", "sizeScale")) + r"""
const AN_SIZE_KEYS = new Set(['an_betweenness']);   // an analysis run's sizes
const state = { metrics: { nodes: [] }, metricById: new Map(), sizeMetric: 'degree', graph: null };
function world(degrees) {
  const nodes = degrees.map((d, i) => ({ id: 'n' + i, deg: d }));
  state.metricById = new Map(nodes.map((n) => [n.id, { degree: n.deg }]));
  state.graph = { nodes, live: nodes.filter((n) => n.deg > 0) };
  const size = sizeScale();
  const out = {};
  for (const n of nodes) out[n.deg] = Math.round(size(n) * 100) / 100;
  return out;
}
console.log(JSON.stringify({ nightjar: world([0, 1, 5, 8, 13, 18]),
                             kestrel: world([2, 3, 4, 8]), flat: world([0, 0]) }));
"""
    got = _run(script)
    nj, ks = got["nightjar"], got["kestrel"]
    assert nj["18"] == 16 and ks["8"] == 16
    # Area in proportion: 18 ties is 3.6 times the ink of 5.
    assert abs((nj["18"] / nj["5"]) ** 2 - 18 / 5) < 0.05, nj
    assert abs((ks["8"] / ks["2"]) ** 2 - 8 / 2) < 0.05, ks
    assert ks["2"] > 7, "the least connected actor is a bare dot again"
    assert nj["0"] == nj["1"] == 5, "the floor is not where 0 and 1 tie meet"
    assert got["flat"]["0"] == 8
    assert "Math.log1p" not in _fn("sizeRaw") + _fn("sizeScale")


def test_the_legend_carries_a_size_key():
    html = _html()
    legend = _between('<div class="legend"', 'id="proj-readout"', html)
    assert 'id="size-key"' in legend
    key = _fn("noteSizeKey")
    assert "NODE_R_MAX * Math.sqrt(ref / hi)" in key, "the key's circles do not follow the scale"
    assert "noteSizeKey(g);" in _fn("noteView")
    script = "\n".join(_fn("sizeKeyRef") for _ in [0]) + r"""
console.log(JSON.stringify([sizeKeyRef(18, true), sizeKeyRef(8, true), sizeKeyRef(1, false),
                            sizeKeyRef(1, true), sizeKeyRef(3.7, false)]));
"""
    assert _run(script) == [5, 2, 0.2, None, 1]


# ---------------------------------------------------------------------------
# ux04 density-strip-flattened
# ---------------------------------------------------------------------------

def test_the_density_strip_is_world_time_and_one_spike_cannot_flatten_it():
    script = _fn("pushTime") + _fn("computeTimeSpan") + _fn("densityBarHeight") + r"""
const state = { nodes: [
  { created_at: '2026-09-23T15:00:00Z' },                      // entered, never dated
  { created_at: '2026-09-23T15:00:00Z', first_seen: '2025-01-01T00:00:00Z' },
  { created_at: '2026-09-23T15:00:00Z', valid_from: '2025-06-01T00:00:00Z' },
], edges: [{ valid_from: '2025-03-01T00:00:00Z' }, {}] };
computeTimeSpan();
const peak = 146;
console.log(JSON.stringify({
  points: state.timePoints.length, undated: state.timeUndated,
  spanMax: new Date(state.timeSpan.max).toISOString().slice(0, 10),
  bars: [densityBarHeight(146, peak, 16), densityBarHeight(14, peak, 16),
         densityBarHeight(1, peak, 16), densityBarHeight(0, peak, 16)],
}));
"""
    got = _run(script)
    assert got["points"] == 3 and got["undated"] == 2, got
    assert got["spanMax"] == "2026-09-23", "the span no longer reaches now"
    full, fourteen, one, none = got["bars"]
    assert full == 16 and none == 0
    assert fourteen > 4 > one >= 2, "a month of 14 reads like a month of 1 again"
    density = _fn("drawDensity")
    assert "tlCtx.lineWidth = 2" not in density, "the 2px playhead is back over the last bar"
    assert "PLAYHEAD_CARET" in density
    assert "undated" in _fn("renderScrubber")


# ---------------------------------------------------------------------------
# ux04 victims-painted-as-groups, legend-missing-drawn-encodings
# ---------------------------------------------------------------------------

def test_a_victim_is_not_drawn_as_a_group():
    assert "VICTIM: 'square'" in _const("SHAPE_BY_TYPE")
    draw = _fn("draw")
    assert "nodeOutline(shape, n.sx, n.sy, r)" in draw
    legend = _between('<div class="legend"', 'id="proj-readout"', _html())
    assert 'class="swatch sq hue-actor-group"></i>Victim' in legend
    # The proposal ring sits on a --void backing, apart from any fill.
    ring = _fn("stateRing")
    backing = _between("if (key === 'proposal') {", "canvasDisc(n.sx, n.sy, at);\n  ctx.setLineDash", ring)
    assert "PAINT.void" in backing


def test_the_legend_names_every_mark_the_canvas_draws():
    legend = _between('<div class="legend"', 'id="proj-readout"', _html())
    for mark in ('class="ring anchor"', 'class="ring ego"', 'class="ring prop"',
                 'class="ring sel"', 'class="ring pin"', "hover dims the rest",
                 'class="glyph-node hollow"', 'class="line bead"',
                 'class="swatch dia hue-context"', 'class="swatch dbl hue-actor-person"'):
        assert mark in legend, f"the legend omits {mark}"
    assert "no confidence recorded" in " ".join(legend.split()), (
        "the full-opacity case is not explained")
    css = APP_CSS.read_text(encoding="utf-8")
    assert ".ring.anchor" in css and ".ring.ego" in css
    # The three accent rings differ by PATTERN: solid, dashed, double.
    draw = _fn("draw")
    assert "stateRing(n, 'anchor', PAINT.accent, [2, 4])" in draw
    assert "stateRing(n, 'ego', PAINT.accentDim, [], EGO_SECOND)" in draw
    assert "stateRing(n, 'selected', PAINT.accent, [])" in draw
