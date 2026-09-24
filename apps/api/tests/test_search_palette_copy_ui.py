"""The Search pane, the Ctrl+K palette and the copy findings closed with
them (ux09-search and ux19-copy, 2026-09-23), held by reading and running
the shipped files.

Pure, like test_ui_invariants.py beside it: no database and no browser.
The checks marked `needs_node` EXECUTE the shipped functions under Node
with small stubs, because "a jump centres the entity" or "a refusal names
the roles" is a claim about what a function does; they skip where Node is
not installed. The database half is test_search_columns_pg.py.
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
SRC = STATIC.parents[1]
ROUTERS = STATIC.parents[0] / "routers"

_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8").replace("\r\n", "\n")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8").replace("\r\n", "\n")


def _css() -> str:
    return (STATIC / "app.css").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first column-0 `}`."""
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    """A top-level `const NAME = ...;` statement, to its first line-final `;`."""
    js = _js()
    m = re.search(r"(?m)^const " + re.escape(name) + r"\b", js)
    assert m, f"const {name} is gone"
    return js[m.start():js.index(";\n", m.start()) + 2]


def _visible(html: str) -> str:
    return re.sub(r"<!--.*?-->", "", html, flags=re.S)


def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text("\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


_API_ERROR = """
class ApiError extends Error {
  constructor(status, title, detail) { super(title); this.status = status;
    this.title = title; this.detail = detail; }
}
"""


# ---------------------------------------------------------------------------
# two-searches-disagree: the header control, the palette's rule, its dead end
# ---------------------------------------------------------------------------

def test_the_header_control_is_called_what_it_opens():
    """It said "Search" with a magnifier and opened the palette, while the
    rail's Search pane gave different answers to the same query."""
    button = re.search(r'<button id="btn-palette".*?</button>', _html(), flags=re.S)
    assert button, "index.html has lost #btn-palette"
    text = button.group(0)
    assert 'class="appbar-search-label">Jump to</span>' in text
    assert 'aria-label="Jump to an entity, a pane or a command"' in text
    assert ">Search<" not in text


def test_the_palette_and_the_pane_find_entities_by_one_route():
    """The palette's server lookup is the pane's Entities route, so for an
    entity the palette finds at least what the pane finds ("umbra" was 3
    there and 10 here)."""
    assert "cpath('/search/nodes?with_total=true" in _fn("fetchPaletteSelectors")
    assert "'/search/' + kind" in _fn("searchPath")
    assert "row: (hit, q) => hitButton(hit, q, 'nodes'" in _js()


@needs_node
def test_a_typed_query_always_ends_on_a_full_search_row(tmp_path):
    """"remittance" answered "Nothing matches." with the text already
    typed and no way on; "hostmarket" found 26 there and 0 in the pane.
    Now the last row runs the full search with the query, and a spaced
    query reaches the server unless it names a command."""
    got = _run([_fn("paletteSearchRow"), _fn("paletteMatches"),
                _fn("commandMatched"), _fn("palSelectorQuery"),
                _const("PAL_SEL_LABELLED"),
                "function paletteFirstScreen(a) { return a; }",
                "let searched = null;",
                "function searchCaseFor(q) { searched = q; }",
                "const state = { caseId: 'c1' };"], """
const items = [
  { kind: 'View', label: 'Go to Graph', hint: 'sociogram, network, canvas' },
  { kind: 'Layout', label: 'Fit view', hint: 'zoom to the graph' },
  { kind: 'Entity', nodeId: 'n1', label: 'Umbra crew', hint: 'Group' },
];
const row = paletteSearchRow('remittance');
row.run();
console.log(JSON.stringify({
  label: row.label, kind: row.kind, searched: searched,
  none: paletteMatches(items, 'remittance').length,
  graph: paletteMatches(items, 'graph').map((it) => it.label),
  spacedEntity: palSelectorQuery('umbra crew',
    commandMatched(paletteMatches(items, 'umbra crew'))),
  spacedCommand: palSelectorQuery('fit view',
    commandMatched(paletteMatches(items, 'fit view'))),
  short: palSelectorQuery('um', false),
}));
""", tmp_path)
    assert got["label"] == 'Search this case for "remittance"'
    assert got["kind"] == "Search" and got["searched"] == "remittance"
    assert got["none"] == 0
    assert "Go to Graph" in got["graph"], "typing 'graph' does not find the Graph pane"
    assert got["spacedEntity"] == "umbra crew"
    assert got["spacedCommand"] == "", "a command spent the search meter"
    assert got["short"] == ""
    render = _fn("renderPalette")
    assert "if (state.caseId && raw) matches.push(paletteSearchRow(raw));" in render
    assert "selectTab('search')" in _fn("searchCaseFor")
    assert "runSearch(" in _fn("searchCaseFor")


# ---------------------------------------------------------------------------
# one-concept-many-names: the rail's words are the palette's words
# ---------------------------------------------------------------------------

def _rail() -> dict[str, str]:
    """data-tab -> the caption the rail shows."""
    out = {}
    for m in re.finditer(r'data-tab="([a-z-]+)".*?<span class="rail-cap[^"]*">([^<]+)</span>',
                         _html(), flags=re.S):
        out[m.group(1)] = m.group(2)
    return out


def test_each_palette_pane_row_uses_the_rail_caption():
    """The palette said "Sociogram", "Entity list" and "Add relationship"
    for tiles captioned Graph, Entities and Link, so "link" found
    nothing."""
    block = re.search(r"const TAB_NAMES = \[(.*?)\];", _js(), re.S).group(1)
    rows = re.findall(r"\['([a-z-]+)', '([^']+)', '([^']*)'\]", block)
    rail = _rail()
    assert len(rows) == len(rail) >= 17
    for key, label, also in rows:
        assert rail[key] == label, (key, rail[key], label)
        assert also, f"the {key} row offers no other words to find it by"
    by_key = {key: (label + " " + also).lower() for key, label, also in rows}
    for word in ("link", "relationship"):
        assert word in by_key["add-edge"], word
    assert "sociogram" in by_key["graph"] and "retention" in by_key["governance"]


def test_the_rail_says_add_and_records():
    rail = _rail()
    assert rail["add-node"] == "Add entity" and rail["add-edge"] == "Add link"
    assert rail["governance"] == "Records", (
        "an analyst told to close a case picked Lifecycle and got retention")
    assert re.search(r"^\.rail-cap\.rail-cap-two \{", _css(), flags=re.M)
    assert 'aria-label="Records sections"' in _html()


def _server_strings() -> list[tuple[str, str]]:
    """`(file, literal)` for every string the server can say: each string
    constant in the package that is not a docstring."""
    import ast

    found = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {
            id(node.body[0].value) for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef))
            and node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)}
        found += [(path.name, node.value) for node in ast.walk(tree)
                  if isinstance(node, ast.Constant)
                  and isinstance(node.value, str)
                  and id(node) not in docstrings]
    return found


def test_nothing_a_reader_sees_sends_them_to_lifecycle():
    """u23 (2026-09-24): the rail tab became Records and two strings
    written in the same pass still said Lifecycle. The readiness register
    told an operator to confirm retention rules "under Lifecycle,
    Retention" one line above the console's own "then Records, Retention",
    and a case review notification offered "Open Lifecycle". No tab, pane
    or section is called that, so every word a reader can see is checked:
    the console's strings, the page's text, the server's strings and the
    manual's headings."""
    word = re.compile(r"\bLifecycle\b")
    js = [s for s in re.findall(r"'(?:[^'\\\n]|\\.)*'", _code(_js()))
          if word.search(s)]
    html = re.findall(r".{0,30}\bLifecycle\b.{0,30}", _visible(_html()))
    server = [(name, text) for name, text in _server_strings()
              if word.search(text)]
    manual = (SRC.parents[3] / "release" / "MANUAL.md").read_text(
        encoding="utf-8")
    headings = [line for line in manual.splitlines()
                if line.startswith("#") and word.search(line)]
    assert (js, html, server, headings) == ([], [], [], []), (
        js, html, server, headings)
    assert "### Records: retention, destruction, break-glass" in manual


def test_the_pane_a_rail_tile_opens_is_headed_in_the_tiles_words():
    """The rail said "Add link" and the pane it opened "Add relationship"
    (verifier of one-concept-many-names, 2026-09-23)."""
    html = _visible(_html())
    pane = html[html.index('id="pane-add-edge"'):]
    pane = pane[:pane.index("</section>")]
    assert '<h2 class="h-sm">Add link</h2>' in pane
    assert ">Create link</button>" in pane
    assert "Add relationship" not in html and "Create relationship" not in html
    assert "A link records one relationship between two" in pane


def test_the_analysis_pane_calls_an_entity_an_entity():
    """"Actor" was the Analysis pane's word for what every other pane
    calls an entity, 13 times in the console and 13 in the page
    (verifier of one-concept-many-names, 2026-09-23). The Deception pane's
    "the actor's tracking pixel" is the sender, a person, not an entity."""
    html = _visible(_html())
    an = html[html.index('id="pane-analytics"'):]
    an = an[:an.index("</section>")]
    assert not re.search(r"\bactors?\b", an, flags=re.I), (
        re.findall(r".{30}\bactors?\b.{30}", an, flags=re.I))
    assert '<option value="1">1 entity</option>' in an
    assert '<option value="3" selected>3 entities</option>' in an
    strings = re.findall(r"'(?:[^'\\\n]|\\.)*'", _code(_js()))
    visible = [s for s in strings if re.search(r"\bactors?\b", s, flags=re.I)
               and not re.fullmatch(r"'actor-[a-z]+'", s)]
    assert visible == [], visible


def test_a_removal_set_of_one_is_not_these_1_entities():
    assert ("'Removing ' + (Number(r.n_remove) === 1 ? 'this entity'"
            in _fn("renderKeyPlayer"))


def test_the_canvas_legend_says_what_the_header_control_says():
    html = _html()
    assert 'id="canvas-keys-palette">Ctrl K</span> jump to' in html
    assert '<h2 id="palette-heading" class="sr-only">Jump to</h2>' in html


def test_the_default_view_is_named_all_social_ties_and_says_what_it_leaves_out():
    projections = (SRC / "projections.py").read_text(encoding="utf-8")
    assert '"label": "All social ties"' in projections
    assert '"label": "All ties"' not in projections
    assert "label: 'All social ties'" in _js() and "label: 'All ties'" not in _js()
    assert "socialSplit(state.edges)" in _fn("renderEntities")


@needs_node
def test_the_entity_count_separates_social_ties_from_identity_links(tmp_path):
    got = _run([_fn("socialSplit"),
                "function countOf(n, one, many) { return n + ' ' + (n === 1 ? one : many); }",
                """const state = { ontology: { edge_types: [
                     { key: 'VOUCHED_FOR', is_social_tie: true },
                     { key: 'SAME_AS', is_social_tie: false }] } };"""], """
const e = (t) => ({ edge_type: t });
console.log(JSON.stringify([
  socialSplit([e('VOUCHED_FOR'), e('VOUCHED_FOR'), e('SAME_AS')]),
  socialSplit([e('VOUCHED_FOR')]),
]));
""", tmp_path)
    assert got[0] == (" (2 social ties and 1 identity or other link, which the "
                      "All social ties view leaves out)")
    assert got[1] == ""


# ---------------------------------------------------------------------------
# palette-first-screen-and-keycap
# ---------------------------------------------------------------------------

@needs_node
def test_the_empty_palette_opens_on_entities_not_seventeen_go_to_rows(tmp_path):
    got = _run([_fn("paletteFirstScreen"), _fn("noteRecentEntity"),
                "const RECENT_ENTITIES = 6; let recentEntities = [];",
                "const FIRST_SCREEN_ENTITIES = 1;",
                "function countOf(n, one, many) { return n + ' ' + (n === 1 ? one : many); }",
                "const state = { caseId: 'c1' };"], """
const all = [];
for (let i = 0; i < 17; i += 1) all.push({ kind: 'View', label: 'Go to P' + i });
all.push({ kind: 'Layout', label: 'Fit view' });
all.push({ kind: 'Focus', label: 'Ego network of a' });
for (const id of ['a', 'b', 'c', 'd']) all.push({ kind: 'Entity', nodeId: id, label: id, hint: 'Persona' });
noteRecentEntity('c'); noteRecentEntity('a');
const first = paletteFirstScreen(all);
console.log(JSON.stringify(first.map((it) => [it.kind, it.label, it.hint || '', !!it.expand])));
""", tmp_path)
    assert got[0] == ["Entity", "a", "recent · Persona", False]
    assert got[1] == ["Entity", "c", "recent · Persona", False]
    assert got[2][0] == "Focus"
    assert got[3] == ["View", "Go to a pane…", "17 panes, listed by name", True]
    views = [row for row in got if row[0] == "View"]
    assert len(views) == 1, "the seventeen Go to rows are not collapsed"
    # Recent first, then a first handful before the commands (one here),
    # then the rest after them.
    assert [row[1] for row in got if row[0] == "Entity"] == ["a", "c", "b", "d"]
    assert got[4] == ["Entity", "b", "Persona", False]
    assert got[5][1] == "Fit view" and got[6][1] == "d"
    assert "noteRecentEntity(id)" in _fn("selectNode")
    run = _fn("runPaletteItem")
    assert run.index("if (it.expand)") < run.index("closePalette()"), (
        "the expanding row closes the palette instead of opening the panes")


def test_every_keycap_follows_the_platform():
    """The canvas strip said ⌘K on Windows beside a header saying Ctrl K."""
    init = _fn("initPalette")
    for cap in ("palette-key", "keys-palette", "canvas-keys-palette"):
        assert f"$('{cap}').textContent = mac ? '⌘K' : 'Ctrl K';" in init, cap
    assert 'id="canvas-keys-palette"' in _html()


# ---------------------------------------------------------------------------
# jump-does-not-reveal
# ---------------------------------------------------------------------------

@needs_node
def test_a_jump_centres_the_entity_and_zooms_in_never_out(tmp_path):
    got = _run([_fn("jumpToEntity"), "const JUMP_SCALE = 1; const ZOOM_MAX = 6;"], """
const calls = [];
const n = { id: 'w', x: 1000, y: -2000 };
const state = { needFit: false, selection: null,
  view: { scale: 0.155, tx: 0, ty: 0 },
  graph: { index: new Map([['w', n]]), revealed: null } };
const canvas = { clientWidth: 1000, clientHeight: 400 };
function selectNode(id) { state.selection = { kind: 'node', id: id }; calls.push('select'); }
function selectTab(t) { calls.push('tab:' + t); }
function takeView() { calls.push('take'); }
function draw() { calls.push('draw'); }
function banner(t) { calls.push('banner:' + t); }
function labelOf(id) { return 'entity ' + id; }
jumpToEntity('w');
const first = { scale: state.view.scale, sx: n.x * state.view.scale + state.view.tx,
  sy: n.y * state.view.scale + state.view.ty,
  revealed: state.graph.revealed === state.selection };
state.view.scale = 3;
jumpToEntity('w');
const zoomedIn = state.view.scale;
jumpToEntity('gone');
console.log(JSON.stringify({ first, zoomedIn, calls }));
""", tmp_path)
    assert got["first"] == {"scale": 1, "sx": 500, "sy": 200, "revealed": True}
    assert got["zoomedIn"] == 3, "a jump zoomed an analyst's closer view out"
    assert got["calls"][:2] == ["select", "tab:graph"]
    assert "banner:Not drawn in this view" in got["calls"], (
        "an entity the projection leaves out is jumped to in silence")


def test_every_jump_from_search_and_the_palette_goes_through_jumpToEntity():
    js = _js()
    assert "row: (hit, q) => hitButton(hit, q, 'nodes', () => jumpToEntity(hit.id))" in js
    assert "run: () => jumpToEntity(n.id)," in _fn("buildPaletteItems")
    assert "run: () => jumpToEntity(hit.id)," in _fn("addSelectorMatches")
    assert "jumpToEntity(a.element_id)" in _fn("openAssertionHit")


# ---------------------------------------------------------------------------
# hit-rows-unexplained
# ---------------------------------------------------------------------------

def test_a_hit_row_carries_chips_and_a_reason_and_no_bare_rank():
    button = _code(_fn("hitButton"))
    assert "toFixed" not in button and "'rank'" not in button
    assert "hitChips(hit)" in button
    chips = _fn("hitChips")
    assert "'chip type-chip ' + hueClass(hit.node_type)" in chips
    assert "'TLP:' + hit.classification" in chips
    assert not re.search(r"^\.hit \.rank", _css(), flags=re.M), "dead .rank rule"
    assert re.search(r"^\.hit-chips \{", _css(), flags=re.M)
    router = (ROUTERS / "search.py").read_text(encoding="utf-8")
    for field in ("node_type: str | None = None", "classification: str | None = None",
                  "in_label: bool = False"):
        assert field in router, field


@needs_node
def test_every_hit_says_why_it_is_there(tmp_path):
    """A query split across parts names the parts, and never claims the
    name unless the server says the name holds a word: "meridian exchange"
    found 18 personas through crew and first_seen_forum, and every row said
    "via the name and attributes together" (verifier of
    hit-rows-unexplained, 2026-09-23)."""
    got = _run([_fn("nameReason"), _fn("exhibitReason"), _fn("assertionReason"),
                _fn("listWords"),
                "function visibleText(s) { return String(s); }"], """
console.log(JSON.stringify([
  nameReason({ in_label: true }),
  nameReason({ in_label: false, attributes: ['crew', 'first_seen_forum'] }),
  nameReason({ in_label: false, attributes: ['crew'], label_part: true }),
  nameReason({ in_label: false, attributes: ['a', 'b', 'c'], label_part: true }),
  nameReason({ in_label: false }),
  exhibitReason({ in_label: true }), exhibitReason({ in_label: false }),
  assertionReason({ matched_in: 'grading', grading: 'C3' }),
  assertionReason({ matched_in: 'exhibit', exhibit_title: 'escrow.eml' }),
  assertionReason({ matched_in: 'rationale' }),
  assertionReason({ matched_in: 'reference', external_ref: 'T-7' }),
  assertionReason({ matched_in: 'claim' }),
]));
""", tmp_path)
    assert got == ["via the name",
                   "via attributes crew and first_seen_forum",
                   "via the name and attribute crew",
                   "via the name and attributes a, b and c",
                   "via its name or attributes",
                   "via the title", "via the description or extracted text",
                   "via the grading C3", "via the cited exhibit escrow.eml",
                   "via the rationale", "via the reference T-7",
                   "via the claimed value"]
    assert "name and attributes together" not in _js()


def test_the_split_reason_reaches_the_pane_from_the_route():
    router = (ROUTERS / "search.py").read_text(encoding="utf-8")
    assert "attributes: list[str] = []" in router
    assert "label_part: bool = False" in router
    assert "attributes=list(h.attributes)" in router
    # The palette gives a server hit the same reason the pane does.
    assert ("|| (hit.in_label ? typeName(hit.node_type) : nameReason(hit))"
            in _fn("addSelectorMatches"))


# ---------------------------------------------------------------------------
# documents-unsearchable and assertions-unsearchable
# ---------------------------------------------------------------------------

def test_the_pane_searches_four_kinds_each_by_its_own_route():
    block = _const("SEARCH_COLUMNS")
    for kind in ("nodes", "evidence", "documents", "assertions"):
        assert re.search(rf"^  {kind}: \{{", block, flags=re.M), kind
        assert f'id="search-{kind}"' in _html(), kind
    router = (ROUTERS / "search.py").read_text(encoding="utf-8")
    for route in ('"/search/documents"', '"/search/assertions"'):
        assert f"@router.get({route}" in router, route
    run = _fn("runSearch")
    assert "SEARCH_KINDS.map((kind) => api(searchPath(kind, q, SEARCH_FIRST)))" in run


def test_a_kind_the_caller_may_not_search_says_so_and_never_no_matches():
    hits = _fn("renderHits")
    assert "page.not_searched" in hits
    assert hits.index("page.not_searched") < hits.index("column.none")
    show = _fn("showSearchColumn")
    assert "status === 403" in show and "notSearched(" in show
    assert "'Not searched. '" in _fn("notSearched")


def test_a_document_is_shown_and_never_linked():
    doc = _code(_fn("documentHit"))
    assert "external_url" not in doc and "href" not in doc
    assert "el('div', 'hit hit-static')" in doc
    assert "fmtTime(d.posted_at)" in doc, "a posting time without its zone"
    assert "visibleText(d.excerpt)" in doc and "visibleText(d.source_name)" in doc


def test_an_assertion_hit_opens_its_element_and_its_card():
    hit = _fn("assertionHit")
    assert "openAssertionHit(a)" in hit and "visibleText(a.element_label)" in hit
    assert "edgeTypeName(a.edge_type)" in hit
    opener = _fn("openAssertionHit")
    assert "selectEdge(a.element_id)" in opener and "relTieCache.set(" in opener
    assert "caseChanged(token)" in opener
    wait = _fn("showCardWhenLoaded")
    assert "focusAssertionCard(assertionId)" in wait
    assert "sel.kind + ':' + sel.id !== key" in wait, (
        "the wait does not give up when the analyst selects something else")


# ---------------------------------------------------------------------------
# ux19-copy: raw enums, opacity, the readout, refusals, help and banners
# ---------------------------------------------------------------------------

@needs_node
def test_a_relationship_type_is_shown_by_its_display_name(tmp_path):
    got = _run([_fn("edgeTypeName")], """
const state = { ontology: { edge_types: [
  { key: 'COMMUNICATES_WITH', display_name: 'communicates with' }] } };
console.log(JSON.stringify([edgeTypeName('COMMUNICATES_WITH'), edgeTypeName('NEW_TYPE')]));
""", tmp_path)
    assert got == ["communicates with", "NEW_TYPE"]
    inspector = _fn("renderInspector")
    assert "typeChip.textContent = edgeTypeName(e.edge_type);" in inspector
    assert "typeChip.textContent = e.edge_type;" not in inspector
    assert "edgeTypeName(l.ref.edge_type)" in _fn("drawLabels")


def test_the_inspector_prints_no_opacity_as_a_confidence():
    metrics = _code(_fn("renderNodeMetrics"))
    assert "'Best tie confidence'" in metrics
    assert "conf || 'No confidence claimed'" in metrics
    assert "' / ' + nodeConfAlpha" not in metrics
    # The scope chip names the preset as the dropdown does, not by its key.
    assert "scope.textContent = presetRow ? presetRow.label : presetKey;" in metrics
    assert "' · tie confidence ' + e.confidence" in _fn("renderInspector")
    assert "'assertion confidence ' + a.confidence" in _fn("renderAssertions")


@needs_node
def test_the_view_is_written_in_the_words_of_its_controls(tmp_path):
    got = _run([_fn("viewWords"), _fn("viewParameters"),
                "function countOf(n, one, many) { return n + ' ' + (n === 1 ? one : many); }",
                "function fmtTime(x) { return x + ' UTC'; }",
                """const state = { proj: { preset: 'all', include_inferred: false,
                     min_confidence: 'LOW', as_of: null },
                   presets: [{ key: 'all', label: 'All social ties' }] };"""], """
console.log(JSON.stringify([
  viewWords({ preset: 'all', include_inferred: true, min_confidence: 'LOW' }),
  viewWords({ label: 'Trust', preset: 'trust', include_inferred: false,
              min_confidence: 'HIGH', as_of: '2026-01-01', edge_types: ['A', 'B'] }),
  viewParameters({ preset: 'all', include_inferred: true, min_confidence: 'LOW' }),
]));
""", tmp_path)
    assert got[0] == ("View: All social ties · confidence LOW and above · "
                      "inferred included · as of now")
    assert got[1] == ("View: Trust · 2 relationship types · confidence HIGH and above"
                      " · inferred left out · as of 2026-01-01 UTC")
    assert got[2] == "preset=all include_inferred=true min_confidence=LOW as_of=now"
    readout = _code(_fn("renderReadout"))
    assert "viewWords(p)" in readout and "'preset='" not in readout
    assert "'projection: '" not in readout
    assert "viewWords(p)" in _fn("projectionSentence")
    analysis = _code(_fn("renderAnalytics"))
    assert "viewWords(p)" in analysis
    assert "dyads" not in analysis and ">=" not in analysis


@needs_node
def test_a_refusal_names_the_roles_and_who_can_give_one(tmp_path):
    """"Approvals need case.read on this case." named a code and nobody who
    could help."""
    got = _run([_API_ERROR, _fn("refusalText"), _fn("closeClause"),
                _fn("permissionRefusal"), _fn("roleWords"), _fn("rolesFor"),
                _fn("listWords"), """let permissionRoles = {
  names: new Map([['ANALYST', 'Analyst'], ['CASE_OWNER', 'Lead investigator'],
                  ['SECURITY_OFFICER', 'Security officer'],
                  ['MALWARE_ANALYST', 'Malware analyst']]),
  holders: { 'case.read': ['ANALYST', 'CASE_OWNER'],
             'break_glass.review': ['SECURITY_OFFICER'],
             'sample.detonate': [] } };"""], """
const e = (d) => new ApiError(403, 'Forbidden', d);
console.log(JSON.stringify([
  refusalText(e('missing permission case.read on this case'),
              'Approvals need case.read on this case.'),
  refusalText(e('missing global permission break_glass.review'),
              'The review belongs to the security officer.'),
  refusalText(e('missing global permission break_glass.review'), ''),
  refusalText(new Error('x'), 'The sample queue needs sample.detonate. The MALWARE_ANALYST role.'),
  refusalText(e('re-authentication required'), 'Approvals need case.read.'),
  refusalText(e('case does not exist'), 'Ask the owner.'),
  roleWords('case.read opens it. So does the case.read permission.'),
  roleWords('The case.read permission opens it.'),
]));
""", tmp_path)
    # A code that opens a sentence opens it with a capital: "Refused. the
    # Security officer role is granted to ..." (verifier, 2026-09-23).
    assert got[6] == ("The Analyst or Lead investigator role opens it. So does "
                      "the Analyst or Lead investigator role.")
    assert got[7] == "The Analyst or Lead investigator role opens it."
    assert got[0] == ("Refused. Approvals need the Analyst or Lead investigator "
                      "role on this case. Ask this case's Lead investigator.")
    assert got[1] == ("Refused: this needs the Security officer role. The review "
                      "belongs to the security officer. Ask an administrator.")
    assert got[2] == "Refused: this needs the Security officer role. Ask an administrator."
    assert got[3] == ("The sample queue needs a permission no role holds in this "
                      "deployment. The Malware analyst role.")
    assert got[4].startswith("Re-authentication required") and "case.read" not in got[4]
    assert got[5] == "Case does not exist. Ask the owner."
    assert "onCaseSwitch(() => { loadPermissionRoles(); });" in _js()
    assert "api('/roles/holders')" in _fn("loadPermissionRoles")
    # The table is the server's (test_role_names_ui): no copy here.
    assert "PERMISSION_ROLES" not in _js() and "ROLE_DISPLAY" not in _js()
    assert "@router.get(\"/holders\"" in (ROUTERS / "roles.py").read_text(encoding="utf-8")


@needs_node
def test_a_case_form_problem_names_the_field_by_its_label(tmp_path):
    got = _run([_fn("fieldProblemText"), _const("CASE_FIELD_LABELS"),
                _fn("listWords")], """
console.log(JSON.stringify([
  fieldProblemText('body.retention_until: Input should be a valid date or datetime, '
    + 'input is too short; body.review_due: Input should be a valid date',
    CASE_FIELD_LABELS),
  fieldProblemText('body.mystery: odd', CASE_FIELD_LABELS),
  listWords(['Code', 'Title', 'Review due']), listWords(['a', 'b'], 'or'),
]));
""", tmp_path)
    assert got[0] == ("Retention until: Input should be a valid date or datetime, "
                      "input is too short. Review due: Input should be a valid date.")
    assert got[1] == "body.mystery: odd."
    assert got[2] == "Code, Title and Review due" and got[3] == "a or b"
    create = _fn("createCase")
    for label in ("'Code'", "'Title'", "'Retention until'", "'Review due'"):
        assert label in create, f"{label} is not checked before the request"
    assert create.index("missing.length") < create.index("await api('/cases'")


def test_no_design_reference_or_session_plumbing_reaches_the_analyst():
    visible = _visible(_html())
    assert not re.search(r"[Ii]nvariant \d", visible), "an invariant number on screen"
    assert "CHECK constraint" not in visible
    assert "number somebody" not in visible and "by missing it" not in visible
    detail = _const("HALF_SESSION_DETAIL")
    assert "CSRF" not in detail and "bootstrap.py" not in detail
    assert "bootstrap.py" not in _fn("doLogin")
    fetch = _fn("_fetch")
    assert "p.detail || 'Sign in again to continue.'" not in fetch
    comms = (ROUTERS / "comms.py").read_text(encoding="utf-8")
    assert "docs/16 L4 is BLOCKING" not in comms
    assert "(docs/16 L4)\")" not in (SRC / "comms.py").read_text(encoding="utf-8")
    retention = (SRC / "retention.py").read_text(encoding="utf-8")
    assert "See docs/16 D3." not in retention
    assert "shipped by migration 0032" not in retention, "a migration number in a purge warning"
    items = _code(_fn("buildPaletteItems"))
    for hint in ("from /graph/metrics", "refetches the projection",
                 "PUT positions", "settle the simulation"):
        assert hint not in items, hint


def test_no_string_in_the_console_cites_a_design_document_or_invariant():
    """"(invariant 10)", "Invariant 12:", "(docs/16 L4)": the analyst has
    no access to either and no use for the number."""
    from test_ui_copy_no_dashes import js_tokens
    literals, _ = js_tokens((STATIC / "app.js").read_text(encoding="utf-8"))
    cited = [text for _, text in literals
             if re.search(r"docs/\d\d|[Ii]nvariant \d|\bPhase \d", text)]
    assert not cited, cited


@needs_node
def test_a_lapsed_session_says_why_in_words(tmp_path):
    """The sign-in sheet printed "Your session has ended (the server said:
    no session token)." (verifier of developer-speak-in-copy, 2026-09-23)."""
    got = _run([_fn("lapseReason")], """
console.log(JSON.stringify([
  lapseReason('no session token'), lapseReason('invalid or expired session'),
  lapseReason('unknown user'), lapseReason(undefined),
]));
""", tmp_path)
    assert got[0].startswith("Your session has ended: this browser no longer holds")
    assert got[2].endswith("Ask an administrator.")
    assert got[1] == got[3]
    for line in got:
        assert "server said" not in line and "session token" not in line, line
    lapse = _fn("describeLapse")
    assert "lapseReason(info.detail)" in lapse and "(the server said: '" not in lapse


#: Server files whose strings are the OPERATOR's: startup refusals and log
#: lines (config, limits) and the readiness register, a checklist for
#: whoever deploys, who has the documents it cites. And egress's "invariant
#: 8", which that module keeps on purpose (the tests that tie the refusal
#: to the rule assert on it).
_OPERATOR_COPY = {"config.py", "readiness.py", "http/limits.py", "egress.py"}


def test_no_server_string_a_console_user_reads_cites_a_design_document():
    """The verifier of developer-speak-in-copy (2026-09-23) found the L4
    notice fixed and its twin, "docs/16 L2 is BLOCKING and unresolved",
    printed when a key is issued, with "docs/10:", "(docs/12)", "(docs/08)"
    and "(invariant 12)" in refusals, proposal rationales and notifications.
    Docstrings, comments and OpenAPI descriptions are not read in the
    console and are not checked."""
    import ast
    cited = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        if rel in _OPERATOR_COPY:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        unread = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                unread.add(id(node.value))          # docstrings
            if isinstance(node, ast.keyword) and node.arg == "description":
                unread.update(id(n) for n in ast.walk(node.value))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in unread
                    and re.search(r"docs/\d\d|\binvariant \d", node.value)):
                cited.append(f"{rel}:{node.lineno}: {node.value[:80]}")
    assert not cited, cited


def test_the_lab_banner_title_is_not_the_notice_again():
    policy = _fn("loadSamplePolicy")
    title = re.search(r"el\('strong', null, '([^']+)'\)", policy).group(1)
    samples = (ROUTERS / "samples.py").read_text(encoding="utf-8")
    notice = re.search(r'"notice": \(\s*"([^"]+)"', samples).group(1)
    assert not notice.startswith(title.rstrip(".")), (title, notice)


def test_the_timeline_button_says_what_it_does():
    button = re.search(r'<button id="btn-asof-now"[^>]*>([^<]+)</button>', _html())
    assert button and button.group(1) == "Jump to now"


def test_the_brokerage_help_is_an_instruction():
    text = " ".join(_visible(_html()).split())
    assert "run it on the Analysis pane to see who bridges two clusters" in text
    assert "Phase 3" not in text
