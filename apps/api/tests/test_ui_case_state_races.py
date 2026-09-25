"""Case state that outlived its case, and a grant whose end went unseen.

The adversarial review of the merged 2026-09-23 console (group g06,
console-case-state) found each of these with a reply or a value that
belonged to one case, or one ceiling, drawn under another:

- C3: the Analysis pane kept NIGHTJAR's ranked, named actors under
  KESTREL's header, and a Run still out at the switch stopped KESTREL
  from ever loading its own stored run.
- C16: a NIGHTJAR /graph reply still out at the switch repainted the
  cleared canvas, because the switch never moved `state.graphSeq`.
- U15: NIGHTJAR's saved layout could replace KESTREL's for the visit, and
  the next Save layout overwrote KESTREL's stored placement.
- C18: a capture paste, an exhibit file and title, and ACH and assumption
  wording typed on one case were written into the next.
- U14: a Lab sample submitted with the Case field blank landed unattached
  and vanished from the case-scoped queue.
- C13 and C17: the header chip saw a grant end through one timer that was
  never re-armed, and a grant change re-read the lists but left the Search
  pane read under the other ceiling.

Behavioural where it matters: the shipped functions run under node with a
fake DOM and an `api` held open, so a test decides when each reply lands
(the harness shape of `test_ui_case_switch_and_dates.py`). Static checks
hold the rest. Skips the node halves when node is not installed.
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

DASHES = ("\u2014", "\u2013", "&mdash;", "&ndash;")


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


def _reset(marker: str) -> str:
    """The one `onCaseSwitch(() => { ... });` registration holding `marker`."""
    js = _js()
    found = []
    for m in re.finditer(r"\nonCaseSwitch\(\(\) => \{", js):
        body = js[m.start():js.index("\n});", m.start()) + 4]
        if marker in body:
            found.append(body)
    assert len(found) == 1, f"expected one reset holding {marker!r}, got {len(found)}"
    return found[0] + "\n"


def _between(start: str, end: str) -> str:
    js = _js()
    a = js.index(start)
    return js[a:js.index(end, a)]


def _node_binary() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    win = Path("C:/Program Files/nodejs/node.exe")
    return str(win) if win.exists() else None


def _run_node(script: str) -> dict:
    node = _node_binary()
    if not node:
        pytest.skip("node is not installed; the static checks still run")
    res = subprocess.run([node, "-"], input=script, capture_output=True,
                         text=True, encoding="utf-8", env=dict(os.environ),
                         timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


#: A fake DOM, a case switch, and an `api` whose replies the test lands.
_PRELUDE = r"""
const nodes = {};
function mk(id) {
  return { id, value: '', checked: false, hidden: false, disabled: false,
    textContent: '', className: '', title: '', children: [], files: [],
    classList: { s: new Set(), add(c) { this.s.add(c); },
      remove(c) { this.s.delete(c); },
      toggle(c, on) { if (on) this.s.add(c); else this.s.delete(c); } },
    appendChild(c) { this.children.push(c); return c; } };
}
function $(id) { if (!nodes[id]) nodes[id] = mk(id); return nodes[id]; }
function el(tag, cls, text) { const n = mk(null); n.tag = tag; n.cls = cls;
  n.textContent = text || ''; return n; }
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
function setMsg(n, text) { n.textContent = text || ''; n.hidden = !text; }
function opts(select, pairs, selected) {
  clear(select);
  for (const [value, label] of pairs) select.appendChild({ value, label });
  const hit = pairs.find(([v]) => v === selected);
  select.value = hit ? hit[0] : (pairs.length ? pairs[0][0] : '');
}
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail; }
}
const resets = [];
function onCaseSwitch(fn) { resets.push(fn); }
const state = { caseId: 'case-a', caseSeq: 1, caseRec: { code: 'OP-A' },
  proj: { preset: 'all' }, presetMap: new Map(), graphSeq: 0, nodeLimit: 500,
  gnodes: [], layout: new Map() };
function caseToken() { return state.caseSeq; }
function caseChanged(t) { return t !== state.caseSeq; }
function cpath(p) { return '/cases/' + state.caseId + p; }
/* What openCase does, in its order: the resets run, then the id moves. */
function switchTo(id, code) {
  state.caseSeq += 1;
  for (const r of resets) r();
  state.caseId = id;
  state.caseRec = { code };
}
const calls = [];
function api(path, o) {
  return new Promise((resolve, reject) => calls.push({ path, o, resolve, reject }));
}
function take(fragment) {
  const i = calls.findIndex((c) => c.path.includes(fragment));
  if (i < 0) throw new Error('no call for ' + fragment + ' in '
    + JSON.stringify(calls.map((c) => c.path)));
  return calls.splice(i, 1)[0];
}
const failed = [];
function fail(err) { failed.push(String(err && err.title || err)); }
const banners = [];
function banner(title, detail, kind) { banners.push({ title, detail, kind }); }
const tick = () => new Promise((r) => setImmediate(r));
const out = {};
"""


# ---------------------------------------------------------------------------
# C3: the Analysis pane
# ---------------------------------------------------------------------------

def _analysis_harness() -> str:
    js = _js()
    consts = js[js.index("const AN_EMPTY_TEXT = "):js.index("\n/** What a failed analysis request")]
    return _PRELUDE + r"""
let drawn = [];
let historyDrawn = [];
let kppLoads = [];
function renderAnalytics() { drawn.push(state.analytics.tag); show($('an-results'), true);
  show($('an-empty'), false); $('an-projection').textContent = 'Projection: '
  + state.analytics.tag; }
function renderMetricHistory() { historyDrawn.push(state.analyticsHistory.tag); }
function histRow() { return el('tr'); }
function drawHistory() {}
function renderList(listId, emptyId, rows) { clear($(listId)); show($(emptyId), !rows.length); }
function anQuery() { return new URLSearchParams({ preset: state.proj.preset }); }
function safeLabelsDeep(x) { return x; }
function fmtTime(v) { return String(v); }
function refusalText(err, fallback) { return fallback; }
function visibleText(s) { return s; }
function countOf(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }
function closeClause(t) { return String(t || ''); }
/* The 2026-09-23 additions, each held by its own test elsewhere: the Node
   size control and the key-player card are not what C3 is about. */
function syncAnalysisSizeOptions() {}
function loadKeyPlayer(storedOnly) { kppLoads.push(storedOnly); }
function loadConcor() {}
""" + consts + "\n" + "".join(_fn(n) for n in (
        "analysisFailureText", "ageText", "currencyText", "storedRunStatus",
        "blankAnalytics", "invalidateAnalytics", "runAnalysis",
        "loadLatestAnalysis", "loadMetricHistory")) + _reset("blankAnalytics(AN_EMPTY_TEXT)") + r"""
function snap() {
  return { analytics: state.analytics ? state.analytics.tag : null,
    results: !$('an-results').hidden, empty: $('an-empty').textContent,
    projection: $('an-projection').textContent, status: $('an-status').textContent,
    runDisabled: $('an-run').disabled, drawn: drawn.slice(), failed: failed.slice() };
}
"""


def test_a_switch_empties_the_analysis_pane_and_a_404_leaves_it_empty():
    """The verifier's deterministic path: NIGHTJAR's latest run is on
    screen, KESTREL was never analysed, so its /analytics/latest is a 404
    that returns quietly. NIGHTJAR's table stayed under KESTREL's header."""
    script = _analysis_harness() + r"""
(async () => {
  $('an-empty').textContent = 'markup text';
  loadLatestAnalysis(); await tick();
  take('/cases/case-a/analytics/latest').resolve({ tag: 'A', computed_at: 't' });
  await tick();
  out.before = snap();
  switchTo('case-b', 'OP-B');
  loadLatestAnalysis(); await tick();
  take('/cases/case-b/analytics/latest').reject(new ApiError(404, 'Not Found', ''));
  await tick();
  out.after = snap();
  out.emptyText = AN_EMPTY_TEXT;
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["before"]["results"] and got["before"]["analytics"] == "A", (
        "the harness never drew case A, so the checks below prove nothing")
    after = got["after"]
    assert after["analytics"] is None
    assert not after["results"], "case A's results are still shown under case B"
    assert after["projection"] == "", "case A's projection caption survived"
    assert after["empty"] == got["emptyText"]
    assert after["failed"] == [], "a 404 on a never-analysed case is not a malfunction"


def test_a_run_answered_after_a_switch_is_dropped_and_b_still_loads():
    """The race: A's Run lands after the switch, set state.analytics, and
    loadLatestAnalysis then never asked for B's run at all."""
    script = _analysis_harness() + r"""
(async () => {
  runAnalysis(); await tick();
  out.running = snap();
  switchTo('case-b', 'OP-B');
  out.switched = snap();
  take('/cases/case-a/analytics?').resolve({ tag: 'A', computed_at_ms: 5 });
  await tick(); await tick();
  const kpp = calls.findIndex((c) => c.path.includes('/cases/case-a/analytics/key-player'));
  out.askedKeyPlayer = kpp >= 0;
  out.afterReply = snap();
  loadLatestAnalysis(); await tick();
  out.askedB = calls.some((c) => c.path.includes('/cases/case-b/analytics/latest'));
  take('/cases/case-b/analytics/latest').resolve({ tag: 'B', computed_at: 't' });
  await tick();
  out.final = snap();
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["running"]["runDisabled"] and got["running"]["status"] == "computing..."
    assert not got["switched"]["runDisabled"], "the switch leaves Run disabled by A's run"
    a = got["afterReply"]
    assert a["analytics"] is None and a["drawn"] == [], (
        f"case A's run was kept and drawn inside case B: {a}")
    assert not got["askedKeyPlayer"], "A's run went on to spend the key-player run"
    assert not a["runDisabled"], "A's late finally must not touch B's button"
    assert got["askedB"], "B's own stored run was never asked for"
    assert got["final"]["drawn"] == ["B"]


def test_a_changed_projection_retires_a_run_and_a_stored_read_in_flight():
    """Same case, other parameters: the reply is for a projection that is no
    longer on screen. invalidateAnalytics returned early when nothing was
    drawn yet, so the reply drew the old projection's numbers."""
    script = _analysis_harness() + r"""
(async () => {
  runAnalysis(); await tick();
  invalidateAnalytics();
  take('/analytics?').resolve({ tag: 'old', computed_at_ms: 5 });
  await tick(); await tick();
  out.run = snap();

  loadLatestAnalysis(); await tick();
  invalidateAnalytics();
  take('/analytics/latest').resolve({ tag: 'stored-old', computed_at: 't' });
  await tick();
  out.latest = snap();

  // A Run started while a stored read is out wins over it.
  loadLatestAnalysis(); await tick();
  runAnalysis(); await tick();
  take('/analytics/latest').resolve({ tag: 'stored', computed_at: 't' });
  await tick();
  out.overtaken = snap();
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    run = got["run"]
    assert run["drawn"] == [] and run["analytics"] is None, run
    assert "projection changed" in run["empty"], "the dropped run is not explained"
    assert not run["runDisabled"], "Run stays disabled after its reply was set aside"
    assert got["latest"]["drawn"] == [], "a stored run for the old projection was drawn"
    assert got["overtaken"]["drawn"] == [], "a stored run was drawn over a fresh Run"


def test_a_trend_for_the_case_left_behind_is_not_charted():
    script = _analysis_harness() + r"""
(async () => {
  $('an-hist-metric').value = 'betweenness';
  loadMetricHistory('node-a', 'umbra_shrike'); await tick();
  switchTo('case-b', 'OP-B');
  take('/cases/case-a/analytics/history/node-a').resolve({ tag: 'A', series: [1] });
  await tick();
  out.afterSwitch = { drawn: historyDrawn.slice(), who: $('an-hist-who').textContent,
    node: state.analyticsHistoryNode };
  // Two actors picked in turn: only the later one is charted.
  loadMetricHistory('node-1', 'one'); await tick();
  loadMetricHistory('node-2', 'two'); await tick();
  take('/analytics/history/node-2').resolve({ tag: 'two', series: [1] }); await tick();
  take('/analytics/history/node-1').resolve({ tag: 'one', series: [1] }); await tick();
  out.overtaken = historyDrawn.slice();
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["afterSwitch"] == {"drawn": [], "who": "", "node": None}, got
    assert got["overtaken"] == ["two"], got["overtaken"]


def test_the_reset_text_is_the_markup_text():
    """The reset restores the pane's own opening sentence, so a switch does
    not leave "The projection changed" or an error from the other case."""
    js = _js()
    an = re.search(r"const AN_EMPTY_TEXT = ('[^;]*);", js, re.S).group(1)
    an = "".join(re.findall(r"'([^']*)'", an))
    hist = re.search(r"const AN_HIST_EMPTY_TEXT = '([^']*)';", js).group(1)
    html = _html()

    def markup(element_id: str) -> str:
        start = html.index(f'id="{element_id}"')
        text = html[html.index(">", start) + 1:html.index("</p>", start)]
        return re.sub(r"\s+", " ", text).strip()

    assert markup("an-empty") == an
    assert markup("an-hist-empty") == hist


# ---------------------------------------------------------------------------
# C16: the sociogram
# ---------------------------------------------------------------------------

def _canvas_harness() -> str:
    return _PRELUDE + r"""
const rendered = [];
function projQuery() { return new URLSearchParams(); }
function withSafeLabel(n) { return n; }
function indexProjection() {}
async function refreshMetrics() {}
async function reapplyFocus() { rendered.push(state.gnodes.map((n) => n.id)); }
function renderProjectionBar() {}
function renderInspector() {}
function analyticsAfterGraphRefresh() {}
function stopWorkerLayout() {}
function stopGraph() { state.graph = null; }
function setCanvasText() {}
function draw() {}
""" + _fn("refreshSociogram") + _reset("stopGraph();")


def test_a_sociogram_reply_from_the_case_left_behind_never_repaints():
    script = _canvas_harness() + r"""
(async () => {
  // Control: no switch, the reply is drawn.
  refreshSociogram(); await tick();
  take('/cases/case-a/graph?').resolve({ nodes: [{ id: 'a0' }], edges: [] });
  await tick(); await tick();
  out.control = rendered.slice();

  refreshSociogram(); await tick();
  switchTo('case-b', 'OP-B');
  take('/cases/case-a/graph?').resolve({ nodes: [{ id: 'a1' }], edges: [] });
  await tick(); await tick();
  out.gnodes = state.gnodes.map((n) => n.id);
  out.rendered = rendered.slice();

  refreshSociogram(); await tick();
  switchTo('case-c', 'OP-C');
  take('/cases/case-b/graph?').reject(new ApiError(500, 'Server Error', ''));
  await tick();
  out.failed = failed.slice();
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["control"] == [["a0"]], "the harness never drew, so this proves nothing"
    assert got["gnodes"] == ["a0"] and got["rendered"] == [["a0"]], (
        f"case A's projection was written and painted after the switch: {got}")
    assert got["failed"] == [], "a failure for the case left behind raised a banner"


def test_every_sociogram_guard_is_moved_by_the_switch():
    """refreshSociogram, enterEgo, enterPath and reapplyFocus all compare
    against state.graphSeq, so moving it in the canvas reset retires all
    four. Held statically for the three the harness does not run."""
    assert "state.graphSeq = (state.graphSeq || 0) + 1;" in _reset("stopGraph();")
    for name in ("enterEgo", "enterPath", "reapplyFocus"):
        assert "seq !== state.graphSeq" in _fn(name), name
    assert "if (seq === state.graphSeq) fail(err);" in _fn("refreshSociogram")


# ---------------------------------------------------------------------------
# U15: the saved layout and the presets
# ---------------------------------------------------------------------------

def test_a_layout_or_presets_reply_for_the_case_left_behind_writes_nothing():
    script = _PRELUDE + _fn("loadLayout") + _fn("loadPresets") + r"""
(async () => {
  loadLayout(); loadPresets(); await tick();
  switchTo('case-b', 'OP-B');
  loadLayout(); loadPresets(); await tick();
  take('/cases/case-b/graph/layout').resolve([{ node_id: 'b1', x: 1, y: 2 }]);
  take('/cases/case-b/graph/presets').resolve({ presets: [{ key: 'b' }] });
  await tick();
  take('/cases/case-a/graph/layout').resolve([{ node_id: 'a1', x: 9, y: 9 }]);
  take('/cases/case-a/graph/presets').resolve({ presets: [{ key: 'a' }] });
  await tick();
  out.layout = Array.from(state.layout.keys());
  out.presets = state.presets.map((p) => p.key);

  loadLayout(); loadPresets(); await tick();
  switchTo('case-c', 'OP-C');
  take('/cases/case-b/graph/layout').reject(new ApiError(500, 'Server Error', ''));
  take('/cases/case-b/graph/presets').reject(new ApiError(500, 'Server Error', ''));
  await tick();
  out.afterFailure = Array.from(state.layout.keys());
  out.failed = failed.slice();
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["layout"] == ["b1"], f"case A's positions replaced case B's: {got}"
    assert got["presets"] == ["b"]
    assert got["afterFailure"] == ["b1"] and got["failed"] == [], got


# ---------------------------------------------------------------------------
# C18 and U14: what was typed for one case, written into the next
# ---------------------------------------------------------------------------

def _writes_harness(*names: str) -> str:
    return _PRELUDE + r"""
let smpPolicy = null;
const loaded = [];
function loadTriage() { loaded.push('triage'); }
function loadEvidence() { loaded.push('evidence'); }
function loadSamples() { loaded.push('samples'); }
function inlineProblem(n, err) { setMsg(n, String(err.title || err)); }
function refusalText(err, fallback) { return err.title || fallback; }
function fmtBytes(n) { return n + ' B'; }
function shortId(id) { return String(id).slice(0, 8); }
/* The Lab submit form's gate and its compartment checkboxes (g09,
   ux13-lab:submit-form-ignores-refusal-and-scope, 2026-09-23): nothing
   ticked, and nothing to repaint in this harness. */
function paintSubmitGate() {}
function loadSamplePolicy() {}
$('smp-compartments').querySelectorAll = () => [];
""" + "".join(_fn(n) for n in ("failureReason", "caseCodeNow") + names)


def test_a_write_answered_after_a_switch_is_said_where_it_went_not_drawn_here():
    # countOf is in the harness because runCapture counts through it
    # (README screenshot set review, 2026-09-23). Without it the success
    # banner threw, the catch drew the FAILURE banner, and "OP-A" in its
    # title passed this test for the wrong reason; the title and detail
    # are now held exactly.
    script = _writes_harness("countOf", "runCapture", "uploadEvidence") + r"""
(async () => {
  $('cap-text').value = 'forum dump'; $('cap-class').value = 'AMBER';
  runCapture(); await tick();
  switchTo('case-b', 'OP-B');
  take('/cases/case-a/proposals/capture').resolve({ proposals_created: 3,
    selectors_found: 4, note: '' });
  await tick();
  out.capture = { ok: $('cap-result').textContent, loaded: loaded.slice(),
    banner: banners.pop() || null };

  $('ev-file').files = [{ size: 10 }]; $('ev-title').value = 'Seized phone';
  uploadEvidence({ preventDefault() {} }); await tick();
  switchTo('case-c', 'OP-C');
  take('/cases/case-b/evidence').resolve({ sha256: 'abc' });
  await tick();
  out.evidence = { ok: $('ev-result').textContent, loaded: loaded.slice(),
    banner: banners.pop() || null };
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    cap = got["capture"]
    assert cap["ok"] == "" and "triage" not in cap["loaded"], cap
    assert cap["banner"] and cap["banner"]["title"] == "Captured into OP-A", cap
    assert cap["banner"]["detail"].startswith("3 proposals raised there."), cap
    ev = got["evidence"]
    assert ev["ok"] == "" and "evidence" not in ev["loaded"], ev
    assert ev["banner"] and "OP-B" in ev["banner"]["title"], ev


def test_a_lab_sample_goes_to_the_open_case_unless_no_case_is_chosen():
    """U14: the Case field was a blank uuid box, so the default submit landed
    a sample the case-scoped queue does not list."""
    script = _writes_harness("submitSample", "fillSampleCase") + r"""
(async () => {
  fillSampleCase();
  out.options = $('smp-case').children.map((o) => o.value);
  out.defaultChoice = $('smp-case').value;
  $('smp-file').files = [{ size: 10 }];
  submitSample(); await tick();
  const first = take('/samples');
  out.firstCase = first.o.form.get('case_id');
  first.resolve({ sha256: '0123456789abcdef0123', file_type: 'PE' }); await tick();
  out.firstMsg = $('smp-submit-msg').textContent;

  $('smp-case').value = 'none';
  submitSample(); await tick();
  const second = take('/samples');
  out.secondCase = second.o.form.get('case_id');
  second.resolve({ sha256: '0123456789abcdef0123', file_type: 'PE' }); await tick();
  out.secondMsg = $('smp-submit-msg').textContent;

  // Re-entering Submit on the same case keeps an explicit "No case".
  fillSampleCase();
  out.kept = $('smp-case').value;
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["options"] == ["case", "none"] and got["defaultChoice"] == "case"
    assert got["firstCase"] == "case-a", "the default submit is still unattached"
    assert "on OP-A" in got["firstMsg"], got["firstMsg"]
    assert got["secondCase"] is None
    assert "All cases I can see" in got["secondMsg"], got["secondMsg"]
    assert got["kept"] == "none"
    html = _html()
    tag = re.search(r'<[a-z]+[^>]*id="smp-case"[^>]*>', html).group(0)
    assert tag.startswith("<select"), "the case is still a free-text uuid field"


def test_the_typed_forms_are_emptied_by_the_resets_they_belong_to():
    triage = _reset("'triage-list'")
    for field in ("cap-text", "cap-title", "cap-url", "cap-result", "cap-error"):
        assert f"'{field}'" in triage, f"the triage reset leaves #{field}"
    # The classification select is rebuilt for no case, not only set, since
    # the capture form is fitted to each case's floor (g01, final review
    # c15, 2026-09-24).
    assert "syncCaptureForm(null, '');" in triage, "the triage reset leaves #cap-class"
    assert "$('cap-class')" in _fn("syncCaptureForm")
    case_file = _reset("'ent-body'")
    for field in ("ev-file", "ev-title", "ev-result", "ev-error",
                  "ach-statement", "asm-statement", "asm-basis"):
        assert f"'{field}'" in case_file, f"the case-file reset leaves #{field}"
    lab = _reset("'smp-list'")
    for field in ("smp-file", "smp-note", "smp-case", "smp-submit-msg"):
        assert f"'{field}'" in lab, f"the Lab reset leaves #{field}"


# ---------------------------------------------------------------------------
# C17 and C13: the break-glass chip
# ---------------------------------------------------------------------------

def _glass_harness() -> str:
    js = _js()
    timing = js[js.index("const GLASS_RETRY_MS = "):
                js.index("\nfunction renderGlassChip(")]
    return _PRELUDE + r"""
let now = 1700000000000;
Date.now = () => now;
const timers = [];
let nextTimer = 0;
function setTimeout(fn, ms) { nextTimer += 1; timers.push({ id: nextTimer, fn, ms, live: true });
  return nextTimer; }
function clearTimeout(id) { for (const t of timers) if (t.id === id) t.live = false; }
function liveTimers() { return timers.filter((t) => t.live).map((t) => t.ms); }
const TLP = ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED'];
function tlpRank(name) { return TLP.indexOf(name); }
const SESSION = { lapsed: false };
let glassTimer = null;
let glassHereKey = null;
let searchSeq = 0;
const effects = [];
function reloadAll() { effects.push('reloadAll'); }
function loadEvidence() { effects.push('loadEvidence'); }
function resetPalSel() { effects.push('resetPalSel'); }
function runSearch() { effects.push('runSearch'); }
function clearDeceptionSearch() { effects.push('clearDeceptionSearch'); }
function describeGrant() { return ''; }
function fmtClock(iso) { return iso; }
const document = { createTextNode(t) { return { textContent: t }; } };
function grant(id, fromNowMs) {
  return { id, scope: 'case', case_id: 'case-a', case_code: 'OP-A',
    granted_classification: 'RED', expires_at: new Date(now + fromNowMs).toISOString() };
}
""" + "".join(_fn(n) for n in ("grantRaises", "grantAppliesHere",
                                "noteGlassChange", "refreshSearchForGlass")) + timing + "".join(
        _fn(n) for n in ("renderGlassChip", "refreshGlassChip"))


def test_a_grant_the_server_still_lists_is_asked_about_again_then_stops():
    """The verifier's reproduction: a workstation clock 3 s fast. The expiry
    timer fires while the server still lists the grant, the wait comes out
    below zero, and nothing was ever asked again."""
    script = _glass_harness() + r"""
(async () => {
  const body = (ms) => ({ clearance: 'AMBER', grants: [grant(7, ms)] });
  renderGlassChip(body(10 * 60 * 1000));
  out.normal = liveTimers();
  const waits = [];
  for (let i = 0; i < 6; i += 1) {
    renderGlassChip(body(-2000));
    waits.push(liveTimers());
  }
  out.skewed = waits;
  renderGlassChip({ clearance: 'AMBER', grants: [] });
  out.ended = { timers: liveTimers(), hidden: $('hdr-glass').hidden };
  // A fresh grant after the backoff ran out gets the backoff again.
  renderGlassChip(body(-2000));
  out.again = liveTimers();
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["normal"] == [10 * 60 * 1000 + 1000]
    assert got["skewed"] == [[5000], [15000], [30000], [60000], [], []], (
        "the backoff must re-ask and then stop, never poll for the grant's life")
    assert got["ended"] == {"timers": [], "hidden": True}
    assert got["again"] == [5000]


def test_a_failed_refresh_is_retried_unless_the_session_ended():
    script = _glass_harness() + r"""
(async () => {
  refreshGlassChip(); await tick();
  take('/break-glass/mine').reject(new ApiError(0, 'Cannot reach the API', ''));
  await tick();
  out.network = liveTimers();
  timers.length = 0;
  const lapsed = new ApiError(401, 'Not loaded: your session had ended', '');
  lapsed.handled = true;
  refreshGlassChip(); await tick();
  take('/break-glass/mine').reject(lapsed);
  await tick();
  out.lapsed = liveTimers();
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["network"] == [5000], "a failed refresh is the last word again"
    assert got["lapsed"] == [], "a lapsed session is re-asked by sessionRenewed"
    assert "if (wasLapsed) refreshGlassChip();" in _fn("sessionRenewed")


def test_a_revoke_is_seen_on_the_analysts_next_action_not_by_polling():
    """An officer's "End it now" reached nobody. A timer would have seen it
    and would also have slid the idle window for the grant's whole life, so
    the re-check rides on the analyst's own activity, at most once a
    minute, and only while a grant is listed."""
    script = _glass_harness() + r"""
(async () => {
  renderGlassChip({ clearance: 'AMBER', grants: [grant(7, 3600000)] });
  now += 30000; recheckGlassOnActivity();
  out.tooSoon = calls.length;
  now += 31000; recheckGlassOnActivity(); await tick();
  out.asked = calls.length;
  // The officer revoked it: the answer lists nothing, the chip goes dark
  // and the lists are re-read at the analyst's own clearance.
  take('/break-glass/mine').resolve({ clearance: 'AMBER', grants: [] });
  await tick();
  out.hidden = $('hdr-glass').hidden;
  out.effects = effects.slice();
  now += 120000; recheckGlassOnActivity();
  out.afterEnd = calls.length;
  SESSION.lapsed = true;
  renderGlassChip({ clearance: 'AMBER', grants: [grant(8, 3600000)] });
  now += 120000; recheckGlassOnActivity();
  out.whileLapsed = calls.length;
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["tooSoon"] == 0 and got["asked"] == 1, got
    assert got["hidden"] is True
    assert {"reloadAll", "loadEvidence"} <= set(got["effects"])
    assert got["afterEnd"] == 0, "nothing listed, nothing to ask about"
    assert got["whileLapsed"] == 0, "a press on the sign-in sheet asked with no session"
    region = _between("const GLASS_RETRY_MS = ", "\nasync function refreshGlassChip(")
    assert "setInterval" not in region
    wiring = _fn("initOpsPanes")
    assert "addEventListener('pointerdown', recheckGlassOnActivity, true)" in wiring
    assert "addEventListener('keydown', recheckGlassOnActivity, true)" in wiring


def test_a_grant_change_asks_the_search_pane_again():
    """C13. The graph and exhibits were re-read when the grant that raises
    the open case changed; the Search pane kept what it had read under the
    other ceiling."""
    script = _glass_harness() + r"""
(async () => {
  const live = { clearance: 'AMBER', grants: [grant(7, 3600000)] };
  const none = { clearance: 'AMBER', grants: [] };
  renderGlassChip(live);          // first sight: nothing to compare with
  out.first = { effects: effects.splice(0), seq: searchSeq };
  $('search-q').value = 'umbra'; $('search-scope').textContent = 'Results for "umbra" in OP-A.';
  renderGlassChip(none);          // the grant ended
  out.ended = { effects: effects.splice(0), seq: searchSeq };
  $('search-q').value = ''; $('search-scope').textContent = '';
  $('search-nodes').children = [{}];
  renderGlassChip(live);          // a grant began, no search on screen
  out.began = { effects: effects.splice(0), seq: searchSeq,
    nodes: $('search-nodes').children.length };
  console.log(JSON.stringify(out));
})();
"""
    got = _run_node(script)
    assert got["first"] == {"effects": [], "seq": 0}
    ended = got["ended"]
    assert ended["seq"] == 1, "a search in flight under the old ceiling is not retired"
    assert {"reloadAll", "loadEvidence", "resetPalSel", "runSearch"} <= set(ended["effects"])
    began = got["began"]
    assert began["seq"] == 2 and "runSearch" not in began["effects"]
    assert began["nodes"] == 0
    # The Search pane's deception block goes with its columns (2026-09-23).
    assert "clearDeceptionSearch" in began["effects"]


# ---------------------------------------------------------------------------
# House rule
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ("blankAnalytics", "refreshSearchForGlass",
                                  "armGlassRetry", "recheckGlassOnActivity",
                                  "fillSampleCase", "runCapture"))
def test_no_em_or_en_dash_in_new_copy(name):
    body = _fn(name)
    assert not any(d in body for d in DASHES), f"{name} carries a dash"


def test_no_em_or_en_dash_in_the_new_constants_or_the_lab_form():
    js = _js()
    for start in ("const AN_EMPTY_TEXT = ", "const GLASS_RETRY_MS = "):
        chunk = js[js.index(start):js.index("\nfunction ", js.index(start))]
        assert not any(d in chunk for d in DASHES), start
    html = _html()
    form = html[html.index('id="smp-submit-pane"'):html.index('id="smp-handling-pane"')]
    assert not any(d in form for d in DASHES)
