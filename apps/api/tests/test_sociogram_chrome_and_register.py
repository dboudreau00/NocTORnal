"""The sociogram's chrome, its coverage chip, its caches, Space, the layout's
last save, and the Evidence register's refresh, held to the Alpha 6
release-candidate review (2026-09-24).

- c12: names were placed under the on-canvas chrome (the Pin button cut
  'ember_owl29' down to 'ember'), and one hidden under the names pill was
  counted in that pill.
- c13: the Evidence register never re-read what each exhibit backs after
  a link, a claim, a retraction or another analyst's change.
- u7: the coverage chip counted the whole projection during an ego or a
  set focus while its title said it counted the canvas.
- u8: the metrics cache key left out a tie's evidence flag, so a cached
  answer reported a server and canvas disagreement that did not exist.
- u9: Space re-pressed the rail's Graph tab instead of peeking.
- u10: closing a case with unsaved placements lit the unsaved dot on an
  inert Save layout, then dropped the placements without a word.

Pure, like test_sociogram_canvas and test_sociogram_graph_pane: the
functions are lifted out of app.js and RUN under node against stubs. No
database, no browser. The node runs skip only where node is absent; the CI
runner image ships it.
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


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """One top-level function, `async` and one-liners included."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    first = js[m.start():js.index("\n", m.start())]
    if first.rstrip().endswith("}") and first.count("{") == first.count("}"):
        return first + "\n"
    return js[m.start():js.index("\n}\n", m.start()) + 3]


def _const(name: str) -> str:
    """A top-level `const`, whole: up to the first `;` outside brackets and
    quotes (the declarations lifted here hold no `;` of their own)."""
    js = _js()
    m = re.search(rf"^const {re.escape(name)} = ", js, flags=re.M)
    assert m, f"app.js has no top-level const {name}"
    depth, quote = 0, ""
    for i in range(m.end(), len(js)):
        ch = js[i]
        if quote:
            if ch == quote and js[i - 1] != "\\":
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ";" and depth == 0:
            return js[m.start():i + 1] + "\n"
    raise AssertionError(f"const {name} never ends")


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    guess = r"C:\Program Files\nodejs\node.exe"
    return guess if os.path.exists(guess) else None


def _run(script: str):
    node = _node()
    if not node:
        pytest.skip("node is not installed here; the static checks still ran")
    res = subprocess.run([node, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


_COMMON = r"""
function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }
function countOf(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
function agree(n, one, many) { return n === 1 ? one : many; }
"""


# ---------------------------------------------------------------------------
# c12: names under the canvas chrome
# ---------------------------------------------------------------------------

#: The plates measured on OP-NIGHTJAR-26's ego focus at 1366x768 (canvas
#: 922x455): the evidence chip, Pin, Re-layout, Save layout, Clear pins,
#: Reload; the names pill, zoom out, the zoom level, zoom in, Fit.
_PLATES_1366 = [[8, 8, 355, 22], [582, 8, 36, 27], [623, 8, 71, 27], [697, 8, 81, 27],
                [782, 8, 72, 27], [858, 8, 56, 27], [531, 422, 236, 24],
                [771, 420, 27, 27], [802, 422, 44, 24], [850, 420, 27, 27],
                [881, 420, 33, 27]]

_LABEL_HARNESS = "const PLATES = " + json.dumps(_PLATES_1366) + ";\n" + _COMMON + r"""
const W = 922, H = 455;
const drawn = [];
const ctx = {
  font: '', textAlign: '', textBaseline: '', globalAlpha: 1, fillStyle: '',
  measureText(t) { return { width: t.length * 6.6 }; },
  fillRect() {},
  fillText(t, x, y) { drawn.push({ t: t, x: x, y: y - 1, w: t.length * 6.6 }); },
};
const PAINT = { labelFont: '11px mono', void: '#000', dim: '#555', bright: '#fff',
                label: '#ccc', labelAlpha: 0.9 };
const state = { hoverId: null, proj: { min_confidence: 'LOW' } };
const canvasChrome = { stale: false, boxes: PLATES, top: 35, bottom: 35 };
function chromeBoxes() { return canvasChrome; }
function edgeTypeName(k) { return k; }
""" + "\n".join(_const(c) for c in ("LABEL_H", "LABEL_GAP", "LABEL_PAD", "LABEL_CELL",
                                    "LABEL_CHARS")) + "\n" \
    + "\n".join(_fn(f) for f in ("labelText", "labelWidth", "boxHash", "placeText",
                                 "underChrome", "drawLabels")) + r"""
function scene(nodes) {
  return { nodes: nodes, links: [], shelf: null, loose: [], labelW: new Map(),
           labelsDrawn: 0, labelsWanted: 0 };
}
const node = (id, label, sx, sy, sr) => ({ id: id, ref: { label: label }, sx: sx, sy: sy,
                                           sr: sr || 8, reach: sr || 8 });
function hidden(list) {
  const out = [];
  for (const l of list) {
    for (const b of PLATES) {
      if (l.x < b[0] + b[2] && l.x + l.w > b[0] && l.y < b[1] + b[3] && l.y + 13 > b[1]) {
        out.push(l.t);
        break;
      }
    }
  }
  return out;
}
const out = {};
// A. A seeded crowd over the whole canvas, rows along both chrome bands.
let seed = 11;
const rnd = () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
const crowd = [];
for (let i = 0; i < 90; i += 1) {
  crowd.push(node('n' + i, 'handle_' + i + (i % 3 ? '_long' : ''), 10 + rnd() * 900,
                  i % 3 === 0 ? 12 + rnd() * 40 : (i % 3 === 1 ? 400 + rnd() * 50 : rnd() * 455),
                  5 + (i % 12)));
}
let g = scene(crowd);
drawLabels(g, null, null, W, H, false, boxHash());
out.crowd = { placed: drawn.length, hidden: hidden(drawn), counted: g.labelsDrawn };
// B. The three from the review: a name whose free spots lie under Pin, the
//    evidence chip and the names pill.
drawn.length = 0;
//    Nodes with no name take the spot below the first two, as the rest of
//    the ego network did.
g = scene([node('owl', 'ember_owl29', 590, 30, 8), node('merlin', 'ember_merlin14', 366, 44, 8),
           node('grebe', 'nightjar_grebe63', 600, 412, 8),
           node('b-owl', '', 590, 50, 10), node('b-merlin', '', 366, 64, 10)]);
drawLabels(g, null, null, W, H, false, boxHash());
out.review = { names: drawn.map((l) => l.t), hidden: hidden(drawn), counted: g.labelsDrawn };
// C. The hovered entity is always named, but not under the chrome while a
//    spot on the canvas is clear of it: here every spot is taken by other
//    nodes, and only 'below' is under the names pill.
drawn.length = 0;
const hot = node('hot', 'hover_me', 640, 405, 6);
const block = [node('b1', '', 640, 385, 12), node('b2', '', 682, 404, 12),
               node('b3', '', 598, 404, 12)];
state.hoverId = 'hot';
g = scene([hot].concat(block));
drawLabels(g, null, null, W, H, false, boxHash());
out.hot = { names: drawn.map((l) => [l.t, Math.round(l.x), Math.round(l.y)]),
            hidden: hidden(drawn), counted: g.labelsDrawn };
state.hoverId = null;
// D. A name the chrome covers is not counted even when drawn (a hovered one
//    whose every spot on the canvas is under a plate).
drawn.length = 0;
state.hoverId = 'pinned';
g = scene([node('pinned', 'under_pin', 600, 21, 3)]);
const tight = [[560, 0, 120, 60]];
canvasChrome.boxes = tight;
drawLabels(g, null, null, W, H, false, boxHash());
out.covered = { drawn: drawn.length, counted: g.labelsDrawn };
console.log(JSON.stringify(out));
"""


def test_no_name_is_placed_under_the_canvas_chrome():
    """c12: drawLabels rejected a spot only off the canvas or over a node,
    bead, sign mark or name. Run over a crowd with rows along both chrome
    bands, and over the three names the review saw cut: none is placed
    under a plate, and the names pill counts every name placed."""
    got = _run(_LABEL_HARNESS)
    crowd = got["crowd"]
    assert crowd["placed"] > 20, crowd
    assert crowd["hidden"] == [], f"names under the chrome: {crowd['hidden']}"
    assert crowd["counted"] == crowd["placed"], crowd
    review = got["review"]
    assert sorted(review["names"]) == ["ember_merlin14", "ember_owl29", "nightjar_grebe63"], review
    assert review["hidden"] == [] and review["counted"] == 3, review


def test_the_hovered_name_avoids_the_chrome_and_a_covered_one_is_not_counted():
    got = _run(_LABEL_HARNESS)
    hot = got["hot"]
    assert [n[0] for n in hot["names"]] == ["hover_me"], hot
    assert hot["hidden"] == [], "the hovered name went back under the names pill"
    assert hot["counted"] == 1
    # Every spot under a plate: still drawn (always named), never counted.
    assert got["covered"] == {"drawn": 1, "counted": 0}, got["covered"]


def test_the_label_pass_reads_the_chrome_and_fit_leaves_room_for_it():
    labels = _fn("drawLabels")
    assert "const plates = chromeBoxes().boxes;" in labels
    assert "hash.add(b[0], b[1], b[2], b[3], null)" in labels
    assert "!underChrome(plates, x, y, tw, LABEL_H)" in labels, (
        "the shelf caption can be cut by a chip again")
    assert "if (!underChrome(plates, spots[at], spots[at + 1], tw, LABEL_H)) drawn += 1;" in labels
    assert "const m = fitMargins(w, h);" in _fn("frameAll")
    assert "watchCanvasChrome();" in _fn("initCanvas")
    assert "canvasChrome.stale = true;" in _fn("resizeGraph")


def test_every_plate_in_the_chrome_markup_is_measured():
    """The selector names the plates by class. A chip or button added to
    either row without one of these classes would be invisible to the
    label pass again."""
    html = INDEX.read_text(encoding="utf-8")
    wrap = html[html.index('<div class="canvas-head">'):html.index('<p id="graph-say"')]
    selector = _const("CHROME_PLATES")
    classes = set(re.findall(r"\.([a-z][\w-]*)", selector))
    containers = {"graph-status", "graph-warnings", "graph-empty", "graph-empty-text",
                  "graph-empty-act"}
    for m in re.finditer(r'<(\w+) id="([\w-]+)"[^>]*class="([^"]+)"', wrap):
        tag, ident, cls = m.groups()
        if ident in containers:
            continue
        assert classes & set(cls.split()), f"#{ident} ({cls}) is not in CHROME_PLATES"
    # The warnings are drawn at render time, as chips.
    assert "el('span', 'cs-chip ' + (cls || ''), text)" in _fn("renderCanvasStatus")
    assert ".canvas-head .cs-chip" in selector


_CHROME_HARNESS = r"""
let rafs = [];
function requestAnimationFrame(fn) { rafs.push(fn); return rafs.length; }
let clock = 1000;
const performance = { now: () => clock };
let draws = 0;
function draw() { if (!canvasChrome.nudging) canvasChrome.nudges = 0; draws += 1; }
const sizes = { chip: 355 };
function plate(x, y, w, h, head) {
  return { getBoundingClientRect() { const ww = typeof w === 'function' ? w() : w;
             return { left: 100 + x, top: 50 + y, width: ww, height: h }; },
           closest(sel) { return sel === '.canvas-head' && head ? {} : null; } };
}
const plates = [plate(8, 8, () => sizes.chip, 22, true), plate(582, 8, 36, 27, true),
                plate(531, 422, 236, 24, false), plate(0, 0, 0, 0, true)];
const canvas = { getBoundingClientRect() { return { left: 100, top: 50, width: 922, height: 455 }; } };
const document = { querySelectorAll() { return plates; } };
""" + _const("CHROME_PLATES") + _const("CHROME_NUDGES") + _const("CHROME_CHAIN_MS") \
    + _const("canvasChrome") \
    + "\n".join(_fn(f) for f in ("chromeBoxes", "sameBoxes", "chromeChanged")) + r"""
const out = {};
const c = chromeBoxes();
out.first = { boxes: c.boxes.length, top: c.top, bottom: c.bottom };
// Nothing moved: no frame asked for.
chromeChanged();
out.same = rafs.length;
// The chip grew (a chip's count gained a digit): one frame.
sizes.chip = 362;
chromeChanged();
out.grew = rafs.length;
// A pathological plate that changes on every frame: at most CHROME_NUDGES
// frames in a row, then nothing until a frame the analyst caused.
for (let i = 0; i < 6; i += 1) {
  const fn = rafs.shift();
  if (fn) fn();
  sizes.chip += 7;
  chromeChanged();
}
out.bounded = { draws: draws, pending: rafs.length };
draw();                       // a pan, a hover
sizes.chip += 7;
chromeChanged();
out.again = rafs.length;
// The cap again, from nudges alone, frame after frame.
for (let i = 0; i < 4; i += 1) {
  const fn = rafs.shift();
  if (fn) { clock += 16; fn(); }
  sizes.chip += 7;
  chromeChanged();
}
out.capped = rafs.length;
// A chip that lands a moment later is still the same chain...
clock += 100;
sizes.chip += 7;
chromeChanged();
out.soon = rafs.length;
// ...but one that lands seconds later (a response) is a new change, and
// gets its frame with nobody panning or hovering.
clock += 3000;
sizes.chip += 7;
chromeChanged();
out.later = rafs.length;
console.log(JSON.stringify(out));
"""


def test_a_chrome_change_redraws_once_and_can_never_loop():
    """The chips land after the frame that placed the names (the coverage
    chip, the warnings, the layout progress), so a moved plate asks for one
    more frame; a plate whose size follows the frame (the names pill's
    count) must not be able to ask for one on every frame."""
    got = _run(_CHROME_HARNESS)
    assert got["first"] == {"boxes": 3, "top": 35, "bottom": 33}, got["first"]
    assert got["same"] == 0, "an unchanged chrome asked for a frame"
    assert got["grew"] == 1
    assert got["bounded"]["draws"] == 2 and got["bounded"]["pending"] == 0, got["bounded"]
    assert got["again"] == 1, "a frame the analyst caused did not re-arm the redraw"
    assert got["capped"] == 0 and got["soon"] == 0, got
    # c12 verifier (2026-09-24): after two nudges only a pan or a hover
    # re-armed it, so a chip that landed later stayed over a name.
    assert got["later"] == 1, "a later chrome change waited for the next pan or hover"
    changed = _fn("chromeChanged")
    assert "CHROME_CHAIN_MS" in changed and "canvasChrome.nudgedAt = performance.now();" in changed


# ---------------------------------------------------------------------------
# c12 verifier: a top-level binding named like a browser global
# ---------------------------------------------------------------------------

#: Own properties of the global object that are NOT configurable. A
#: classic script whose top-level `let`, `const` or `class` takes one of
#: these names is a SyntaxError before any of it runs, and a top-level
#: `function` of one a TypeError. The first pass of c12 named its plate
#: cache `const chrome`, and the whole console was dead in the bundled
#: Chromium 151 (new headless), where window.chrome is non-configurable,
#: while the headless shell (no window.chrome) and Chrome 153 (configurable)
#: ran it (c12 verifier, 2026-09-24). Probed on 2026-09-24 in those three
#: builds: window, document, location and top are unforgeable everywhere
#: (the HTML standard's [LegacyUnforgeable]); chrome depends on the build;
#: undefined, NaN and Infinity are the language's own.
_RESERVED_ON_WINDOW = ("window", "document", "location", "top", "chrome",
                       "undefined", "NaN", "Infinity")
#: A dedicated worker's global keeps only the language's own.
_RESERVED_IN_WORKER = ("undefined", "NaN", "Infinity")

_TOP_DECL = re.compile(r"^(?:async\s+)?(?:const|let|var|class|function\*?)\s+([A-Za-z_$][\w$]*)",
                       flags=re.M)


def _top_level_names(js: str) -> set[str]:
    """Every name a top-level declaration binds: the first declarator, and
    any further ones on the same line (`let a = 0, b = 1;`)."""
    names = set(_TOP_DECL.findall(js))
    for m in re.finditer(r"^(?:const|let|var)\s+([^;\n]*)", js, flags=re.M):
        depth = 0
        for i, ch in enumerate(m.group(1)):
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "," and depth == 0:
                nxt = re.match(r"\s*([A-Za-z_$][\w$]*)\s*(?:=|,|$)", m.group(1)[i + 1:])
                if nxt:
                    names.add(nxt.group(1))
    return names


def test_no_top_level_binding_takes_a_name_the_browser_reserves():
    names = _top_level_names(_js())
    assert len(names) > 1000, "the declaration scan found too little to be trusted"
    assert "canvasChrome" in names and "selectTab" in names
    clash = sorted(names & set(_RESERVED_ON_WINDOW))
    assert not clash, f"app.js declares {clash} at top level: a browser refuses the whole file"
    worker = _top_level_names((STATIC / "layout-worker.js").read_text(encoding="utf-8"))
    assert "running" in worker
    assert not sorted(worker & set(_RESERVED_IN_WORKER))


_GLOBALS_HARNESS = r"""
const vm = require('vm');
const RESERVED = %s;
const SOURCE = %s;
/* The global object a browser gives a classic script, as far as the
   declaration check goes: the reserved names are there and cannot be
   redefined. Then the file itself runs. If its declarations clash, nothing
   in it is declared, not even its hoisted functions. */
function load(src) {
  const ctx = vm.createContext({});
  vm.runInContext('for (const k of ' + JSON.stringify(RESERVED) + ') {'
    + ' if (Object.getOwnPropertyDescriptor(globalThis, k)) continue;'
    + ' Object.defineProperty(globalThis, k, { value: {}, writable: false,'
    + ' enumerable: true, configurable: false }); }', ctx);
  let error = null;
  try {
    vm.runInContext(src, ctx, { filename: 'app.js', timeout: 20000 });
  } catch (e) {
    error = String(e && e.name);
  }
  return { error: error, selectTab: vm.runInContext('typeof selectTab', ctx) };
}
console.log(JSON.stringify({
  app: load(SOURCE),
  // The harness sees a clash: the first pass's binding, and a function.
  asChrome: load('const chrome = {};\nfunction selectTab() {}\n'),
  asTop: load('function top() {}\nfunction selectTab() {}\n'),
}));
"""


def test_the_console_script_declares_itself_where_window_chrome_is_fixed():
    """Run the whole of app.js as a classic script against a global where
    every reserved name is non-configurable, as the bundled Chromium 151
    has window.chrome: its functions must be declared (the page runs from
    there; a stub DOM stops it soon after, which is not the point)."""
    script = _GLOBALS_HARNESS % (json.dumps(list(_RESERVED_ON_WINDOW)), json.dumps(_js()))
    got = _run(script)
    assert got["asChrome"] == {"error": "SyntaxError", "selectTab": "undefined"}, got["asChrome"]
    assert got["asTop"]["selectTab"] == "undefined", got["asTop"]
    assert got["app"]["selectTab"] == "function", (
        f"app.js never ran: {got['app']['error']} at declaration time")
    assert got["app"]["error"] != "SyntaxError", got["app"]


# ---------------------------------------------------------------------------
# u7: the coverage chip during a focus
# ---------------------------------------------------------------------------

_COVERAGE_HARNESS = _COMMON + r"""
const box = { textContent: '', className: '', title: '' };
function $() { return box; }
function setMsg(n, t) { n.textContent = t; }
const row = (id, h) => ({ id: id, has_evidence: h });
const gnodes = [], gedges = [];
for (let i = 0; i < 146; i += 1) gnodes.push(row('n' + i, i < 30));
for (let i = 0; i < 446; i += 1) gedges.push(row('e' + i, false));
const state = { gnodes: gnodes, gedges: gedges, metrics: null, projTruncated: false,
                focus: null, graph: null };
function drawnOf(ns, es) {
  return { nodes: ns.map((r) => ({ id: r.id, ref: r })), links: es.map((r) => ({ ref: r })) };
}
""" + "\n".join(_fn(f) for f in ("backedCount", "coverageLine",
                                 "renderEvidenceCoverage")) + r"""
const snap = () => { renderEvidenceCoverage(); return { text: box.textContent, title: box.title }; };
const out = {};
state.graph = drawnOf(gnodes, gedges);
out.whole = snap();
// Meridian crew's ego focus: 19 entities, 85 ties, none of them evidenced.
state.focus = { kind: 'ego', id: 'n40' };
state.graph = drawnOf(gnodes.slice(40, 59), gedges.slice(0, 85));
out.ego = snap();
// A set focus of the evidenced entities and nothing else.
state.focus = { kind: 'set' };
state.graph = drawnOf(gnodes.slice(0, 10), []);
out.set = snap();
// A path focus draws the whole projection.
state.focus = { kind: 'path' };
state.graph = drawnOf(gnodes, gedges);
out.path = snap();
console.log(JSON.stringify(out));
"""


def test_the_coverage_chip_counts_the_focus_on_the_canvas():
    """u7: the ego focus drew 104 elements and the chip said "0 of 592",
    under a title saying it counted the canvas."""
    got = _run(_COVERAGE_HARNESS)
    assert got["whole"]["text"] == "evidence: 30 of 592 elements (5%) rest on an exhibit"
    assert "focus" not in got["whole"]["title"]
    ego = got["ego"]
    assert ego["text"] == "evidence: 0 of 104 elements in this focus (0%) rest on an exhibit", ego
    assert "which shows a focus and not the whole projection" in ego["title"]
    assert "In the whole projection, 30 of 592 elements rest on an exhibit." in ego["title"]
    assert got["set"]["text"] == ("evidence: 10 of 10 elements in this focus (100%) "
                                  "rest on an exhibit")
    assert got["path"] == got["whole"], "a path focus draws the whole projection"


# ---------------------------------------------------------------------------
# u8: the metrics cache key and a tie's evidence
# ---------------------------------------------------------------------------

_METRICS_HARNESS = _COMMON + r"""
class ApiError extends Error {}
const nodes = {};
function $(id) { if (!nodes[id]) nodes[id] = { id, disabled: false }; return nodes[id]; }
const state = { caseId: 'c1', graphSeq: 1, projTruncated: false,
  gnodes: [{ id: 'a', has_evidence: false }, { id: 'b', has_evidence: false }],
  gedges: [{ id: 'e1', src_node_id: 'a', dst_node_id: 'b', weight: 1, sign: 1,
             confidence: 'LOW', is_inferred: false, has_evidence: false }],
  metrics: null, metricById: new Map(), ranks: null, rankTotal: 0, metricsNote: '',
  metricsDown: null, metricsRetry: 0, metricsCache: new Map(), proj: { preset: 'all' } };
function cpath(p) { return '/cases/' + state.caseId + p; }
function projQuery() { const q = new URLSearchParams(); q.set('preset', 'all'); return q; }
const calls = [];
function api(path) {
  calls.push(path);
  // The server counts what rests on an exhibit NOW.
  const backed = state.gedges.filter((e) => e.has_evidence).length;
  return Promise.resolve({ nodes: [], evidence_coverage: { nodes: 0, edges: backed, elements: 3 } });
}
function clearTimeout() {}
const SIZE_METRICS = [['degree', 'Degree']];
""" + "\n".join(_fn(f) for f in ("subgraphKey", "metricsKey", "metricsUp", "refreshMetrics",
                                 "applyMetrics", "computeRanks", "backedCount",
                                 "coverageLine")) + "\n" + _const("METRICS_CACHE_MAX") + r"""
(async () => {
  await refreshMetrics(1, projQuery());
  // An exhibit linked to the tie, then the projection re-read.
  state.gedges[0].has_evidence = true;
  await refreshMetrics(1, projQuery());
  const line = coverageLine(state.gnodes, state.gedges, state.metrics.evidence_coverage, false);
  console.log(JSON.stringify({ calls: calls.length, title: line.title, text: line.text }));
})();
"""


def test_a_tie_linked_to_an_exhibit_is_not_served_the_old_metrics():
    """u8: subgraphKey mixed a node's has_evidence and not a tie's, so the
    metrics answer from before the link was served again and the chip's
    title reported "The metrics service counted 0" against the canvas's 1."""
    got = _run(_METRICS_HARNESS)
    assert got["calls"] == 2, "the link was answered from the cache"
    assert "metrics service counted" not in got["title"], got["title"]
    assert got["text"].startswith("evidence: 1 of 3 elements")
    key = _fn("subgraphKey")
    assert "(e.has_evidence ? '+' : '-')" in key


# ---------------------------------------------------------------------------
# u9: Space on the rail's Graph tab
# ---------------------------------------------------------------------------

def test_space_peeks_from_the_selected_graph_tab_in_the_rail():
    """u9: a click on Graph in the rail leaves the focus on the tab, which
    is outside the pane, and Space re-selected the pane already open."""
    script = r"""
const canvas = { tagName: 'CANVAS' };
const document = { body: { tagName: 'BODY' }, documentElement: { tagName: 'HTML' } };
const state = { tab: 'graph', graph: {} };
function signedIn() { return true; }
function tab(id, selected) {
  return { id: id, tagName: 'BUTTON', type: 'button', isContentEditable: false,
           closest() { return null; },                  // the rail is outside the pane
           getAttribute(n) { return n === 'role' ? 'tab'
             : (n === 'aria-selected' ? (selected ? 'true' : 'false') : null); } };
}
""" + _fn("spacePeeks") + r"""
const out = { graphTab: spacePeeks(tab('tab-graph', true)),
              otherTab: spacePeeks(tab('tab-evidence', false)) };
state.tab = 'evidence';
out.graphTabElsewhere = spacePeeks(tab('tab-graph', false));
console.log(JSON.stringify(out));
"""
    got = _run(script)
    assert got == {"graphTab": True, "otherTab": False, "graphTabElsewhere": False}, got


# ---------------------------------------------------------------------------
# u10: closing a case with placements unsaved
# ---------------------------------------------------------------------------

_LAYOUT_HARNESS = _COMMON + r"""
const state = { caseId: 'A', caseRec: { code: 'OP-A', status: 'ACTIVE' }, graph: { nodes: [] },
                layoutCarry: null, layoutDirty: new Set(), layout: new Map(), focus: null,
                selection: null, view: { scale: 1 }, zoomFloor: 0.1 };
function caseCodeNow() { return state.caseRec ? state.caseRec.code : state.caseId; }
function syncLayoutFromSim() {}
function failureReason() { return 'offline'; }
const puts = [], banners = [];
let refuse = false;
function api(path, o) {
  if (!o) return Promise.resolve([]);
  if (refuse) return Promise.reject(new Error('offline'));
  puts.push({ path, n: o.json.positions.length });
  return Promise.resolve({});
}
function banner(title, text) { banners.push(title + ': ' + text); }
function cpath(p) { return '/cases/' + state.caseId + p; }
let seq = 0;
function caseToken() { return seq; }
function caseChanged(t) { return t !== seq; }
function fail() {}
const CASE_STATES_SHUT = new Set(['CLOSED', 'ARCHIVED', 'PURGED']);
const ZOOM_MAX = 6, ZOOM_MIN = 0.12;
const els = {};
function $(id) {
  if (!els[id]) {
    els[id] = { id, title: '', disabled: false, attrs: {}, cls: new Set(),
      classList: { contains: (c) => els[id].cls.has(c),
                   toggle: (c, on) => { if (on) els[id].cls.add(c); else els[id].cls.delete(c); } },
      setAttribute(k, v) { this.attrs[k] = v; } };
  }
  return els[id];
}
function setDisabled(id, off) { $(id).disabled = off; }
function setCanvasText() {}
function pinScopeIds() { return []; }
function labelOf(id) { return id; }
""" + "\n".join(_fn(f) for f in ("leaveLayout", "loadLayout", "saveLayoutOnLeave",
                                 "saveLayoutBeforeShut", "layoutPositions", "caseReadOnly",
                                 "syncCanvasControls")) + r"""
const tick = () => new Promise((r) => setTimeout(r, 0));
function placed() {
  state.layout = new Map([['n1', { node_id: 'n1', x: 5, y: 6, is_pinned: true }],
                          ['n2', { node_id: 'n2', x: 1, y: 2, is_pinned: false }]]);
  state.layoutDirty = new Set(['n1', 'n2']);
  state.graph = { nodes: [{}] };
}
const dot = () => ({ dirty: $('btn-save-layout').cls.has('dirty'),
                     label: $('btn-save-layout').attrs['aria-label'] || null });
(async () => {
  const out = {};
  // 1. The review's path with no save first: Status to CLOSED re-opens the
  //    SAME case, whose resets run while the record is still ACTIVE.
  placed();
  leaveLayout();
  state.layoutDirty = new Set();
  state.graph = null;
  await tick();
  state.caseRec = { code: 'OP-A', status: 'CLOSED', read_only: true };
  await loadLayout();
  state.graph = { nodes: [{}] };
  syncCanvasControls();
  out.reopened = { n1: state.layout.get('n1'), dirty: Array.from(state.layoutDirty),
                   save: dot() };
  // A drag-free read-only case with a stale dirty set shows no dot either.
  state.layoutDirty = new Set(['n9']);
  syncCanvasControls();
  out.stale = dot();
  // 2. Before the status change is sent: stored, and said.
  state.caseRec = { code: 'OP-A', status: 'ACTIVE' };
  placed();
  await saveLayoutBeforeShut('CLOSED');
  out.saved = { puts: puts.slice(), dirty: state.layoutDirty.size, banner: banners.pop() };
  // Not a read-only destination: nothing is stored behind the analyst's back.
  placed();
  await saveLayoutBeforeShut('DORMANT');
  out.dormant = { puts: puts.length, dirty: state.layoutDirty.size };
  // A failed save is said, and the status change goes ahead.
  refuse = true;
  await saveLayoutBeforeShut('ARCHIVED');
  out.failed = { dirty: state.layoutDirty.size, banner: banners.pop() };
  refuse = false;
  // Already read-only (CLOSED to PURGED): nothing to store.
  state.caseRec = { code: 'OP-A', status: 'CLOSED', read_only: true };
  await saveLayoutBeforeShut('PURGED');
  out.shut = puts.length;
  console.log(JSON.stringify(out));
})();
"""


def test_a_case_closed_with_placements_unsaved_keeps_them_and_says_so():
    got = _run(_LAYOUT_HARNESS)
    # The re-read closed case: the placements are drawn, not marked unsaved.
    assert got["reopened"]["n1"] == {"node_id": "n1", "x": 5, "y": 6, "is_pinned": True}
    assert got["reopened"]["dirty"] == [], "a read-only case's placements marked unsaved"
    assert got["reopened"]["save"] == {"dirty": False, "label": "Save layout"}, got["reopened"]
    assert got["stale"]["dirty"] is False, "the dot shows on a read-only case"
    saved = got["saved"]
    assert saved["puts"] == [{"path": "/cases/A/graph/layout", "n": 2}], saved
    assert saved["dirty"] == 0
    assert saved["banner"].startswith("Layout of OP-A saved: 2 entities you moved or pinned "
                                      "were not saved yet, so they were saved before the "
                                      "change to CLOSED was sent."), saved["banner"]
    # Said before the POST, so it may not claim the change happened (u10
    # verifier, 2026-09-24).
    assert "Once the case is CLOSED, its layout is read-only." in saved["banner"]
    assert "which makes" not in saved["banner"]
    assert got["dormant"] == {"puts": 1, "dirty": 2}, got["dormant"]
    assert got["failed"]["dirty"] == 2
    assert "will not be kept" in got["failed"]["banner"] and "ARCHIVED" in got["failed"]["banner"]
    assert got["shut"] == 1


def test_the_status_change_stores_the_layout_before_it_is_sent():
    submit = _fn("submitStatus")
    save = submit.index("await saveLayoutBeforeShut(to);")
    guard = submit.index("if (caseChanged(token)) return;", save)
    post = submit.index("'/status'")
    assert save < guard < post, "the layout is stored after the case is shut, or unguarded"


# ---------------------------------------------------------------------------
# c13: the Evidence register re-reads what each exhibit backs
# ---------------------------------------------------------------------------

def test_every_route_that_changes_what_an_exhibit_backs_rereads_the_register():
    """c13: loadEvidence ran at case open, after an upload, from Reload and
    on a break-glass change, and nowhere else."""
    select = _fn("selectTab")
    assert "if (name === 'evidence' && state.caseId) loadEvidence({ pageOnly: true });" in select
    reload_all = _fn("reloadAll")
    assert reload_all.index("await refreshSociogram();") < reload_all.index(
        "await reloadRegisterIfShown();")
    linker = _fn("renderEvidenceLinker")
    assert linker.index("refreshSociogram();") < linker.index("reloadRegisterIfShown();")
    # Retire in the inspector re-reads the graph without reloadAll (c13
    # verifier, 2026-09-24): a retired element no longer rests on anything.
    actions = _fn("wireElementActions")
    retire = actions[actions.index("{ method: 'DELETE', json: { reason: reason.trim() } }"):]
    assert retire.index("await loadCaseGraph();") < retire.index("reloadRegisterIfShown();")
    js = _js()
    live = js[js.index("const _refetchSoon = debounce("):]
    live = live[:live.index("}, 900);")]
    assert live.index("await refreshSociogram();") < live.index("await reloadRegisterIfShown();")


_REGISTER_HARNESS = r"""
const cards = {};
let rendered = 0;
const document = { querySelectorAll(sel) {
  return sel === '.ev-item.focused' ? Object.values(cards).filter((c) => c.cls.has('focused')) : [];
} };
function card(id) {
  const c = { id: id, cls: new Set(), scrolled: 0,
              classList: { add: (k) => c.cls.add(k), remove: (k) => c.cls.delete(k) },
              scrollIntoView() { c.scrolled += 1; } };
  return c;
}
const inputs = { 'ev-q': { value: 'phone' }, 'ev-unbacked': { checked: true } };
function $(id) { return inputs[id] || cards[id.replace(/^ev-/, '')] || null; }
const state = { tab: 'graph', caseId: 'c1', evidencePolicy: {}, evidence: [] };
let backs = 0;
const calls = [];
function api(path) {
  if (!/\/index$/.test(path)) calls.push(path);    // the page reads only
  return Promise.resolve({ total: 2, matching: 2, offset: 0, backs_nothing: backs ? 1 : 2,
    items: [{ id: 'x1', backs_nodes: backs }, { id: 'x2', backs_nodes: 0 }] });
}
function cpath(p) { return p; }
function caseToken() { return 0; }
function caseChanged() { return false; }
function clearLoadFailure() {}
function renderEvidencePolicy() {}
function refreshEvidencePickers() {}
// Every render draws fresh cards, as renderEvidence does: a class set on
// the old ones is gone.
function renderEvidence() {
  rendered += 1;
  for (const k of Object.keys(cards)) delete cards[k];
  for (const it of evView.page.items) cards[it.id] = card(it.id);
}
function evidenceQuery(v) { return v.only ? '?evidence_id=' + v.only : '?page'; }
function selectTab(name) {
  state.tab = name;
  if (name === 'evidence' && state.caseId) loadEvidence({ pageOnly: true });
}
""" + _const("evView") + "let evSeq = 0;\nlet evFocus = null;\n" + "\n".join(
    _fn(f) for f in ("loadEvidence", "reloadRegisterIfShown", "markFocusedExhibit",
                     "focusEvidence")) + r"""
const tick = () => new Promise((r) => setTimeout(r, 0));
(async () => {
  const out = {};
  await loadEvidence();                     // case open
  out.open = { calls: calls.length, backs: evView.page.items[0].backs_nodes };
  // A link made on the Entities tab, then the Evidence tab.
  backs = 1;
  await reloadRegisterIfShown();            // not on screen: nothing asked
  out.offScreen = calls.length;
  selectTab('evidence');
  await tick(); await tick();
  out.onSelect = { calls: calls.length, backs: evView.page.items[0].backs_nodes };
  // A write made while the register is showing (the inspector beside it).
  backs = 0;
  await reloadRegisterIfShown();
  out.onScreen = { calls: calls.length, backs: evView.page.items[0].backs_nodes };
  // A jump to an exhibit on the page: marked, and still marked once the
  // re-read the tab change starts has redrawn the cards.
  state.tab = 'graph';
  focusEvidence('x2');
  await tick(); await tick();
  out.focusOnPage = { focused: cards.x2.cls.has('focused'), only: evView.only,
                      q: inputs['ev-q'].value, rendered: rendered };
  // A jump to an exhibit not on the page: asked for alone, then marked.
  state.tab = 'graph';
  const before = calls.length;
  focusEvidence('x9');
  await tick(); await tick();
  out.focusOffPage = { asked: calls.slice(before), only: evView.only,
                       unbacked: inputs['ev-unbacked'].checked };
  console.log(JSON.stringify(out));
})();
"""


def test_the_register_is_read_again_when_shown_and_keeps_a_jump_marked():
    got = _run(_REGISTER_HARNESS)
    assert got["open"] == {"calls": 1, "backs": 0}
    assert got["offScreen"] == 1, "the register was fetched while nobody could see it"
    assert got["onSelect"] == {"calls": 2, "backs": 1}, (
        "selecting the Evidence tab kept the answer from case open")
    assert got["onScreen"] == {"calls": 3, "backs": 0}
    on_page = got["focusOnPage"]
    assert on_page["focused"] is True, "the re-read drew over the jump's mark"
    assert on_page["only"] is None and on_page["q"] == "phone", on_page
    off_page = got["focusOffPage"]
    assert off_page["asked"] == ["/evidence?evidence_id=x9"], off_page
    assert off_page["only"] == "x9" and off_page["unbacked"] is False


# ---------------------------------------------------------------------------
# The copy rules, for everything this pass wrote
# ---------------------------------------------------------------------------

_WRITTEN = ("chromeBoxes", "chromeChanged", "watchCanvasChrome", "drawLabels",
            "fitMargins", "renderEvidenceCoverage", "backedCount", "coverageLine",
            "spacePeeks", "loadLayout", "syncCanvasControls", "saveLayoutBeforeShut",
            "reloadRegisterIfShown", "focusEvidence", "subgraphKey")


@pytest.mark.parametrize("name", _WRITTEN)
def test_this_pass_writes_no_dash_no_lazy_plural_and_no_inline_style(name: str):
    body = _fn(name)
    strings = re.findall(r"'(?:[^'\\\n]|\\.)*'", body)
    bad = [s for s in strings if re.search("[\u2013\u2014]| -- |\\(s\\)", s)]
    assert not bad, bad
    assert ".style" not in body and "innerHTML" not in body, name
