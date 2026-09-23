"""The sociogram painter, held to the encoding docs/06 says never bends.

A 42-agent review on 2026-09-22 found the canvas restyle wanting in ways
no test had noticed, because none looked: the E2 "hollow = unevidenced"
mark read a field the simulation node never carried and so never drew on
any case; node opacity depended on radius; a 0.45 literal borrowed the
confidence channel for provenance; parallel ties could not be clicked;
Fit could not frame the flagship case; labels were all or nothing by zoom
and printed over each other; the keyboard could select what it could not
show. Each check below is named for the defect it would have caught.

These are pure: they read the shipped static assets, like
test_ui_invariants and test_theme_contract. The canvas has no DOM to query,
so the checks read the painter's source. Where a number matters (ring
gaps, the width ramp) it is parsed and measured rather than matched. The
view tests at the end go one step further and RUN the view functions
lifted from app.js under node, against a stub canvas: no database, no
browser, no network.
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
DOCS_06 = Path(__file__).resolve().parents[3] / "docs" / "06-interface.md"


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """The source of one top-level function, up to its closing brace."""
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}\n", start) + 2]


def _const(name: str) -> float:
    m = re.search(rf"^const {name} = ([0-9.]+);", _js(), re.M)
    assert m, f"{name} is gone; update this test with it"
    return float(m.group(1))


# ---------------------------------------------------------------------------
# E2: provenance on the canvas
# ---------------------------------------------------------------------------

def test_unevidenced_is_read_from_the_row_not_the_sim_node():
    """setRendered builds each sim node as {id, ref, deg, x, y, ...}; the
    API's has_evidence lives on `ref`. Every read of `n.has_evidence` was
    undefined, so on every case no entity was ever drawn hollow (cr01
    e2-hollow-core-never-fires)."""
    js = re.sub(r"/\*.*?\*/", "", _js(), flags=re.S)   # prose may name the bug
    assert not re.search(r"\b(?:n|node|sim)\.has_evidence\b", js), (
        "a sim node is asked for has_evidence; the flag is on n.ref")
    assert "n.ref.has_evidence === false" in _fn("nodeUnevidenced")
    assert "nodeUnevidenced(n)" in _fn("draw")


def test_a_hollow_node_is_void_inside_with_no_body_and_no_core():
    """The two states must differ by AREA, not by a 2.5px dot: evidenced
    is body + core, unevidenced is --void inside the ring and nothing else
    (cr02 e2-hollow-core-lost)."""
    draw = _fn("draw")
    start = draw.index("if (nodeUnevidenced(n)) {")
    split = draw.index("} else {", start)
    hollow = draw[start:split]
    evidenced = draw[split:draw.index("\n    }\n", split)]
    assert "PAINT.void" in hollow
    assert "NODE_CORE_FRAC" not in hollow and "bodyAlpha" not in hollow, (
        "a hollow node is painted a body or a core")
    assert "bodyAlpha(conf)" in evidenced and "NODE_CORE_FRAC" in evidenced


def test_an_unevidenced_tie_gets_a_shape_not_a_fade_and_not_a_dash():
    """Opacity is confidence and dashed is inferred; E2 on a tie may borrow
    neither (ux07 unevidenced-fade-hijacks-confidence-opacity)."""
    draw = _fn("draw")
    start = draw.index("if (lit && edgeUnevidenced(e)) {")
    bead = draw[start:draw.index("\n    }\n", start)]
    assert "PAINT.void" in bead and "ctx.stroke()" in bead, "the bead is gone"
    assert "0.45" not in draw
    # The only dash in the edge pass is the inferred one.
    edges = draw[draw.index("/* edges */"):draw.index("/* nodes */")]
    dashes = re.findall(r"setLineDash\(([^)]*)\)", edges)
    assert all(d in ("[]", "e.is_inferred ? [5, 4] : []") for d in dashes), dashes


def test_the_legend_explains_both_e2_marks():
    """The meaning lived only in a checkbox's hover title (ux03
    unevidenced-hollow-never-drawn)."""
    html = INDEX.read_text(encoding="utf-8")
    legend = html[html.index('<div class="legend"'):html.index('id="proj-readout"')]
    assert 'class="glyph-node hollow"' in legend
    assert 'class="line bead"' in legend


# ---------------------------------------------------------------------------
# Opacity is confidence, and only confidence
# ---------------------------------------------------------------------------

def test_one_node_treatment_at_every_radius():
    """Below 5px nodes were solid, above it they had a 0.40 body, so zooming
    one wheel step changed a node's apparent certainty (cr01
    ring-threshold-borrows-opacity-channel)."""
    js = _js()
    assert "NODE_RING_MIN_R" not in js
    draw = _fn("draw")
    assert not re.search(r"\bif \(r\s*[<>]=?", draw), (
        "the node painter branches on radius again")


def test_a_node_with_no_qualifying_tie_is_drawn_at_the_lowest_step():
    """confAlpha(undefined) is 1, so an entity with no tie in the projection
    drew at full, HIGH-looking opacity, and 'HIGH only' made every entity
    look surer (ux03 minconf-isolates-full-opacity)."""
    step = _fn("nodeStep")
    assert "'LOW'" in step
    draw = _fn("draw")
    assert "nodeStep(n.id)" in draw
    assert "state.nodeConf.get(n.id)" not in draw, (
        "the painter reads nodeConf directly and skips the fallback")
    assert "none / 1.00" not in _js(), "the inspector still quotes full opacity"
    # And when the floor emptied the picture, the canvas says it was the floor.
    assert "'no tie in this projection is ' + graded" in _fn("drawLabels")


def test_edge_width_spans_the_observed_weight_range():
    """log1p(w) / log1p(max(1, maxWeight)) on 0..1 ratio weights left the
    bottom half of the ramp unreachable and the flagship case inside one
    pixel (cr01 edge-width-range-under-a-pixel)."""
    body = _fn("edgeWidth")
    assert "Math.max(1" not in body
    assert "g.minWeight" in body and "g.maxWeight" in body
    assert ": 0.5" in body, "all-equal weights must draw one mid width"
    assert _const("EDGE_W_MAX") - _const("EDGE_W_MIN") >= 1.5, (
        "the lightest and heaviest tie must differ by 1.5px or more")
    assert "minWeight" in _fn("setRendered")


# ---------------------------------------------------------------------------
# Rings
# ---------------------------------------------------------------------------

def test_state_rings_stand_clear_of_the_type_ring():
    """The type ring sat ON r and the dashed --alert proposal ring 1px
    outside it, so on a group node pending review merged into the type
    colour (cr02 hue-ring-overloads-state-ring). The type ring is inset
    now (outer edge = r); the first state ring clears it by 3px and no two
    state rings overlap."""
    js = _js()
    block = js[js.index("const STATE_RINGS = {"):]
    block = block[:block.index("};")]
    rings = [(k, float(o), float(w)) for k, o, w in
             re.findall(r"(\w+): \[([0-9.]+), ([0-9.]+)\]", block)]
    assert [k for k, _, _ in rings] == [
        "proposal", "selected", "pinned", "anchor", "ego"]
    _, off, width = rings[0]
    assert off - width / 2 >= 3, "the first state ring is within 3px of the node"
    for (_, o1, w1), (k2, o2, w2) in zip(rings, rings[1:], strict=False):
        assert o2 - w2 / 2 >= o1 + w1 / 2, f"the {k2} ring overlaps the one inside it"
    draw = _fn("draw")
    assert "canvasDisc(n.sx, n.sy, r - ringW / 2)" in draw, "the type ring is not inset"
    for key in ("proposal", "selected", "pinned", "anchor", "ego"):
        assert f"stateRing(n, '{key}'" in draw


# ---------------------------------------------------------------------------
# The ground
# ---------------------------------------------------------------------------

def test_the_key_light_is_painted_once_per_size_and_cannot_throw():
    """A fresh gradient and a second full-canvas fill ran every frame (cr01
    ground-repainted-every-frame), and an unresolved token threw out of
    addColorStop and killed the canvas (cr01 missing-token-now-kills-canvas)."""
    assert "createRadialGradient" not in _fn("paintGround")
    assert "createRadialGradient" not in _fn("draw")
    build = _fn("buildGround")
    assert "createRadialGradient" in build
    assert "PAINT.canvasKeylight && PAINT.canvasKeylightOut" in build
    assert "try {" in build
    assert "buildGround()" in _fn("resizeGraph")
    assert "buildGround()" in _fn("loadPaint")


def test_the_grid_is_one_filled_path():
    """Stroked hairlines composited every crossing twice at DPR 1; the
    contrast model in test_theme_contract assumes once."""
    grid = _fn("paintGrid")
    assert ".rect(" in grid and "ctx.fill()" in grid
    assert "stroke" not in grid


def test_a_throwing_draw_cannot_strand_the_layout_loop():
    """frame() used to call draw() before reassigning g.raf, so a throw left
    a stale id and every `if (!g.raf)` restart guard skipped for good."""
    frame = _fn("frame")
    assert frame.index("g.raf = 0;") < frame.index("draw();")


# ---------------------------------------------------------------------------
# Parallel ties
# ---------------------------------------------------------------------------

def test_parallel_ties_bow_apart_and_the_nearest_is_hit():
    """Two ties on one pair were one straight line: the last drawn was the
    one seen, the first listed the one clicked, so a red dispute opened as
    a green vouch (ux05 parallel-ties-unreachable)."""
    assert "l.bend = " in _fn("setRendered")
    assert "quadraticCurveTo" in _fn("traceLink")
    hit = _fn("edgeAt")
    assert "return l.ref" not in hit, "edgeAt returns the first tie in reach again"
    assert "linkDist(p, linkGeom(l))" in hit and "<= bestD" in hit


# ---------------------------------------------------------------------------
# Fit, the shelf, and the keyboard
# ---------------------------------------------------------------------------

def test_fit_has_no_fixed_floor_and_keeps_fitting_until_the_layout_is_done():
    """fitView clamped to 0.12 and fired on the FIRST worker message, before
    ForceAtlas2 expanded the graph (ux03 fit-cannot-fit-flagship, ux04
    fit-cannot-frame-flagship, ux18 laptop-canvas-fit)."""
    frame_all = _fn("frameAll")
    assert "0.12" not in frame_all
    assert "clamp(fit, FIT_MIN, FIT_MAX)" in frame_all
    assert _const("FIT_MIN") < _const("ZOOM_MIN") / 10, (
        "Fit's floor is back near the wheel's, and a wide graph cannot be framed")
    assert "state.zoomFloor" in _fn("zoomAt")
    worker = _fn("startWorkerLayout")
    assert "state.needFit = false; fitView()" not in worker
    assert "if (state.needFit) frameAll();" in worker


def test_unconnected_entities_are_shelved_not_flung():
    """ForceAtlas2's constant gravity cannot hold an entity with no tie, and
    OP-NIGHTJAR-26's 46 wallets and hosts drifted 3,000 units out."""
    worker = _fn("startWorkerLayout")
    assert "const live = g.live;" in worker
    assert "g.nodes.map" not in worker, "isolates are sent to the worker again"
    assert "const ns = g.live;" in _fn("step")
    assert "shelveIsolates(" in _fn("setRendered")


def test_labels_are_eleven_px_and_placed_rather_than_thresholded():
    """All names above 0.7x and none below, drawn inside the node loop at
    10px, overprinting each other (ux04 labels-all-or-nothing-and-colliding)."""
    js = _js()
    assert "PAINT.labelFont = '11px '" in js
    draw = _fn("draw")
    assert "showLabels" not in draw
    assert draw.index("drawLabels(") > draw.index("/* nodes */"), (
        "labels are drawn before the nodes that would cover them")
    assert "hash.hits(" in _fn("drawLabels")


def test_the_keyboard_can_pan_and_the_view_follows_the_selection():
    """selectNode never moved the view and the canvas had no pan keys
    (ux18 no-keyboard-pan-or-reveal)."""
    keys = _fn("onCanvasKey")
    assert "e.shiftKey && PAN_KEYS[e.key]" in keys
    assert "followSelection(g)" in _fn("draw")
    assert "revealNode(n)" in _fn("followSelection")
    aria = INDEX.read_text(encoding="utf-8")
    assert "Shift with an arrow key pans" in aria


# ---------------------------------------------------------------------------
# Found by the verifier of the first fix pass (2026-09-22 fix round)
# ---------------------------------------------------------------------------

def _case_switch_reset() -> str:
    """The canvas's own onCaseSwitch registration."""
    js = _js()
    start = js.index("onCaseSwitch(() => {\n  stopWorkerLayout();")
    return js[start:js.index("\n});\n", start)]


def test_a_case_switch_drops_the_old_graph_so_the_new_case_is_fitted():
    """openCase kept the previous case's SETTLED graph until the new
    projection arrived, and resizeGraph spent the new case's needFit on
    it: CORVID to NIGHTJAR through the palette left 144 of 146 entities
    off the canvas."""
    reset = _case_switch_reset()
    assert "stopGraph();" in reset, "the old case's graph survives the switch"
    assert "state.needFit = true;" in reset
    resize = _fn("resizeGraph")
    assert "g.settled && frameAll()" in resize, (
        "resizeGraph fits a graph whose layout has not finished")
    # And openCase itself still runs the registry before anything else.
    open_case = _fn("openCase")
    assert open_case.index("runCaseSwitchResets();") < open_case.index("await ")


def test_a_rerender_keeps_the_reveal_and_a_reselection_pans_again():
    """Two ways followSelection disagreed with the analyst. setRendered
    reset `revealed`, so every scrubber step panned back to a selection the
    analyst had panned away from; and it compared ids, so choosing the same
    entity again from the palette did not bring it back."""
    rendered = _fn("setRendered")
    assert "revealed: prevGraph ? prevGraph.revealed : null" in rendered
    follow = _fn("followSelection")
    assert "sel === g.revealed" in follow, "the reveal is keyed on the id again"
    assert "g.revealed = id" not in follow
    for fn in ("selectNode", "selectEdge"):
        assert "state.selection = { kind:" in _fn(fn), (
            f"{fn} no longer builds a fresh selection, so a reselection "
            "would not count as new")


def test_the_view_stays_fitted_until_the_analyst_takes_it():
    """A one-shot fit left 'HIGH only' on NIGHTJAR with 70 of 146 entities
    off the canvas: the projection change moved them onto the shelf and
    nothing re-framed it. A view that is still the fit re-fits; the first
    pan or zoom ends that."""
    assert "state.viewFitted = true;" in _fn("frameAll")
    take = _fn("takeView")
    assert "state.needFit = false;" in take and "state.viewFitted = false;" in take
    for fn in ("zoomAt", "panView", "revealPoint"):
        assert "takeView();" in _fn(fn), f"{fn} moves the view without taking it"
    rendered = _fn("setRendered")
    assert "else if (state.viewFitted) state.needFit = true;" in rendered
    assert "(state.needFit || state.viewFitted)" in _fn("resizeGraph")
    # No gesture may clear needFit behind takeView's back and leave the
    # view marked as fitted.
    region = _js()[_js().index("function initCanvas()"):_js().index("function onCanvasKey(")]
    assert "if (moved) takeView();" in region


def test_every_tie_is_reachable_from_the_keyboard():
    """Arrows reached entities only, so the second tie on a pair (and every
    tie, for a keyboard-only analyst) could not be opened (ux05
    parallel-ties-unreachable)."""
    keys = _fn("onCanvasKey")
    assert "e.key === ']' || e.key === '['" in keys and "stepTie(" in keys
    ties = _fn("tiesOf")
    assert "x.bend - y.bend" in ties, "ties on one pair are not kept together"
    assert "selectEdge(" in _fn("stepTie")
    assert "l.pair = group" in _fn("setRendered")
    assert "link.pair.length" in _fn("noteView"), (
        "a selected tie no longer says it has a twin")
    html = INDEX.read_text(encoding="utf-8")
    sheet = html[html.index('<h3 class="h-xs">Sociogram</h3>'):]
    sheet = sheet[:sheet.index("</dl>")]
    assert '<span class="kbd">[</span>' in sheet, "the ? sheet omits [ and ]"
    assert "square bracket keys" in html, "the canvas's accessible name omits [ and ]"


def test_the_legend_is_whole_at_laptop_heights():
    """Under max-height 820px the legend was one row that scrolled
    sideways; at 1366x768, 'dashed = inferred', opacity and both E2 marks
    sat past the edge, unseen."""
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    start = css.index("@media (max-height: 820px)")
    block = css[start:css.index("\n}\n", start)]
    legend = re.search(r"\.legend \{([^}]*)\}", block)
    assert legend, "the short-height legend rule is gone; update this test"
    assert "nowrap" not in legend.group(1) and "overflow" not in legend.group(1), (
        "the legend is clipped to one row again at laptop heights")


def test_docs_06_describes_the_canvas_that_ships():
    """docs/06 described a flat --void canvas, opaque discs and a ring that
    meant only state (cr02 docs-describe-old-canvas)."""
    docs = DOCS_06.read_text(encoding="utf-8")
    assert "(--void, edge to edge)" not in docs
    for phrase in ("Node shape", "State rings", "Edge bead", "type ring"):
        assert phrase in docs, f"docs/06 does not describe the {phrase}"
    # The fix round's behaviour, written down where the canvas is reviewed.
    flat = " ".join(docs.split())
    assert "view stays the fit" in flat, "docs/06 does not describe the sticky fit"
    assert "`[`/`]`" in flat, "docs/06 does not document stepping through ties"


# ---------------------------------------------------------------------------
# Found by the verifier of the fix round (2026-09-22 review, second pass)
#
# These run the painter's own view functions, lifted out of app.js, under
# node against a stub canvas, because the defect was a NUMBER (a reveal
# margin wider than Fit's padding) that a source grep would not have seen.
# Skipped only where node is absent; the CI runner image ships it.
# ---------------------------------------------------------------------------

def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    for guess in (r"C:\Program Files\nodejs\node.exe",):
        if os.path.exists(guess):
            return guess
    return None


def _top_fn(name: str) -> str:
    """One top-level function, one-liners included (_fn needs a closing
    brace on a line of its own)."""
    js = _js()
    start = js.index(f"\nfunction {name}(") + 1
    first = js[start:js.index("\n", start)]
    if first.rstrip().endswith("}") and first.count("{") == first.count("}"):
        return first
    return js[start:js.index("\n}\n", start) + 2]


_VIEW_FNS = ("clamp", "fitPad", "frameAll", "takeView", "revealNode", "inView",
             "revealPoint", "revealLink", "linkOf", "followSelection",
             "pickOnCanvas", "resizeGraph")

_STUBS = """
const canvas = { clientWidth: 0, clientHeight: 0 };
const window = { devicePixelRatio: 1 };
const ctx = { setTransform() {} };
const state = { view: { scale: 1, tx: 0, ty: 0 }, graph: null, selection: null,
                needFit: false, viewFitted: false, zoomFloor: null, viewport: null };
let draws = 0;
function buildGround() {}
function draw() { draws += 1; if (state.graph) followSelection(state.graph); }
"""

_SCENARIOS = r"""
const out = {};
function setup(w, h) {
  canvas.clientWidth = w; canvas.clientHeight = h;
  let seed = 7;
  const rnd = () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
  const nodes = [];
  for (let i = 0; i < 146; i += 1) {
    // Radii from 3 to 22px: the smallest entity at fit to the largest at 1.6x.
    nodes.push({ id: 'n' + i, x: rnd() * 3200 - 1600, y: rnd() * 2800 - 1400,
                 sr: 3 + (i % 20) });
  }
  const g = { nodes: nodes, links: [], revealed: null, settled: true,
              index: new Map(nodes.map((n) => [n.id, n])) };
  state.graph = g;
  state.view = { scale: 1, tx: 0, ty: 0 };
  state.selection = null;
  state.needFit = false;
  state.viewFitted = false;
  state.viewport = { w: w, h: h, dpr: 1 };
  return g;
}
const screen = (n) => [n.x * state.view.scale + state.view.tx,
                       n.y * state.view.scale + state.view.ty];
const offCanvas = (n) => {
  const s = screen(n);
  return s[0] < 0 || s[1] < 0 || s[0] > canvas.clientWidth || s[1] > canvas.clientHeight;
};
function zoomIn(k) {
  const v = state.view, cx = canvas.clientWidth / 2, cy = canvas.clientHeight / 2;
  v.tx = cx - (cx - v.tx) * k; v.ty = cy - (cy - v.ty) * k; v.scale *= k;
  state.viewFitted = false;
}
const centred = (n) => {
  const s = screen(n);
  return Math.abs(s[0] - canvas.clientWidth / 2) < 0.5 &&
         Math.abs(s[1] - canvas.clientHeight / 2) < 0.5;
};

// A. Selecting any entity of a fitted view keeps the fit.
out.fitted = {};
for (const [w, h] of [[922, 287], [996, 389], [886, 239], [1310, 620]]) {
  const g = setup(w, h);
  frameAll();
  const v0 = JSON.stringify(state.view);
  let moved = 0;
  for (const n of g.nodes) {
    state.selection = { kind: 'node', id: n.id };
    draw();
    if (JSON.stringify(state.view) !== v0 || !state.viewFitted) {
      moved += 1;
      state.view = JSON.parse(v0);
      state.viewFitted = true;
    }
  }
  out.fitted[w + 'x' + h] = moved;
}

// B. Zoomed in, the keyboard still brings an off-canvas entity to the middle.
{
  const g = setup(996, 389);
  frameAll();
  zoomIn(6);
  const off = g.nodes.filter(offCanvas);
  const v0 = JSON.stringify(state.view);
  let revealed = 0;
  for (const n of off) {
    state.view = JSON.parse(v0);   // each one from the same zoomed view
    state.selection = { kind: 'node', id: n.id };
    draw();
    if (centred(n)) revealed += 1;
  }
  out.zoomed = { off: off.length, revealed: revealed };
}

// C. A click never moves the view, even on an entity cut by the rim.
{
  const g = setup(996, 389);
  frameAll();
  zoomIn(6);
  const n = g.nodes.find(offCanvas);
  const v0 = JSON.stringify(state.view);
  pickOnCanvas(() => { state.selection = { kind: 'node', id: n.id }; draw(); });
  out.click = { moved: JSON.stringify(state.view) !== v0,
                recorded: g.revealed === state.selection };
}

// D. A selection made while the pane is hidden is revealed when it is shown,
//    even though the canvas comes back at the same size.
{
  const g = setup(996, 389);
  frameAll();
  zoomIn(6);
  const n = g.nodes.find(offCanvas);
  canvas.clientWidth = 0; canvas.clientHeight = 0;       // another tab
  state.selection = { kind: 'node', id: n.id };
  draw();
  const hiddenRevealed = g.revealed === state.selection;
  canvas.clientWidth = 996; canvas.clientHeight = 389;   // back to the graph
  const before = draws;
  resizeGraph();
  const drew = draws - before;
  const before2 = draws;
  resizeGraph();                                        // nothing pending now
  out.hidden = { hiddenRevealed: hiddenRevealed, drew: drew, centred: centred(n),
                 idleDraws: draws - before2 };
}

// E. A fit the layout finished while the pane was hidden happens on show.
{
  const g = setup(996, 389);
  zoomIn(6);
  state.needFit = true;
  resizeGraph();
  out.pendingFit = { needFit: state.needFit, fitted: state.viewFitted,
                     off: g.nodes.filter(offCanvas).length };
}
process.stdout.write(JSON.stringify(out));
"""


def _run_view_scenarios() -> dict:
    node = _node()
    if not node:
        pytest.skip("node is not installed here; the static checks still ran")
    js = _js()
    assert "\nlet pickedOnCanvas = false;\n" in js, "the pointer-pick flag is gone"
    consts = "\n".join(f"const {c} = {_const(c)};"
                       for c in ("ZOOM_MIN", "ZOOM_MAX", "FIT_MIN", "FIT_MAX"))
    script = "\n".join([_STUBS, consts, "let pickedOnCanvas = false;",
                        *(_top_fn(f) for f in _VIEW_FNS), _SCENARIOS])
    run = subprocess.run([node, "-e", script], capture_output=True, text=True,
                         timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def test_selecting_an_entity_on_a_fitted_view_keeps_the_fit():
    """followSelection counted an entity inside 40px of the rim as hidden,
    and Fit leaves only 29px at 1366x768: arrowing to 'Tessera crew' on a
    fitted NIGHTJAR re-centred the view and put 50 of 146 entities off the
    canvas. Every entity of a fitted view, at every laptop canvas size and
    at every drawn radius, must select without moving it."""
    inview = _top_fn("inView")
    assert "fitPad(w, h) - 1" in inview, "the reveal margin is no longer capped by Fit's"
    assert "Math.min(40" not in inview
    assert "const pad = fitPad(w, h);" in _top_fn("frameAll")
    out = _run_view_scenarios()
    assert out["fitted"] == {"922x287": 0, "996x389": 0, "886x239": 0, "1310x620": 0}, (
        f"selecting on a fitted view moved it: {out['fitted']}")
    # The fix must not cost the reveal itself.
    assert out["zoomed"]["off"] > 10
    assert out["zoomed"]["revealed"] == out["zoomed"]["off"], out["zoomed"]


def test_a_click_never_moves_the_view():
    """A real click on 'Tandem Logistics', at the top rim, moved the view:
    what was clicked is under the pointer and needs no reveal."""
    js = _js()
    pointer = js[js.index("function initCanvas()"):js.index("function onCanvasKey(")]
    assert "pickOnCanvas(() => selectNode(n.id))" in pointer
    assert "pickOnCanvas(() => selectEdge(edge.id))" in pointer
    assert re.search(r"(?<!pickOnCanvas\(\(\) => )select(Node|Edge)\(", pointer) is None, (
        "the pointer handler selects without marking the pick as a click")
    out = _run_view_scenarios()
    assert out["click"] == {"moved": False, "recorded": True}, out["click"]


def test_a_selection_made_on_another_tab_is_revealed_on_return():
    """A search hit or a palette jump selects while the graph pane is
    hidden, so the reveal cannot happen then; selectTab('graph') called
    resizeGraph, which returned early because the size had not changed,
    and the entity stayed at y=-363 on a 389px canvas."""
    out = _run_view_scenarios()
    hidden = out["hidden"]
    assert hidden["hiddenRevealed"] is False, "a reveal into a canvas with no size counted"
    assert hidden["drew"] == 1 and hidden["centred"] is True, hidden
    assert hidden["idleDraws"] == 0, "resizeGraph now repaints when nothing is pending"
    # The same early return also stranded a fit the layout finished unseen.
    assert out["pendingFit"] == {"needFit": False, "fitted": True, "off": 0}, out["pendingFit"]


def test_docs_describe_the_reveal_as_it_behaves():
    """docs/06 said the view follows every selection; ARCHITECTURE said the
    keyboard follows every new selection. Neither held for a selection made
    on another tab, and a click must not move the view at all."""
    flat = " ".join(DOCS_06.read_text(encoding="utf-8").split())
    assert "Three things never pan: a click" in flat
    assert "revealed when the graph tab is shown again" in flat
    arch = (DOCS_06.parents[1] / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "follows every new selection" not in arch
    assert "never a click, never an entity Fit placed" in arch
