"""The ENTITY and LINK create forms: nothing chosen on the analyst's behalf.

Three findings from the 2026-09-22 usability review, each a default the
console picked and the analyst never saw it pick:

- ux06 grading-prefilled-upward: both forms opened on Direct observation /
  C / 3 / MODERATE, so an entity typed and submitted became a graded claim
  nobody graded, pitched above the server's own not-graded F / 6 / LOW.
- ux06 edge-type-defaults-to-scam-accusation: the relationship type took
  the list's first option, which for persona to persona is ACCUSED_SCAM,
  and every endpoint change rebuilt the list and reset the choice to it.
- ux06 edge-endpoint-pickers: two unsearchable selects of every entity,
  both opening on the SAME entity, so the form started on a self-loop.

Plus the client half of ux06 edge-confidence-not-stored: the form's
confidence must travel in the assertion, which since migration 0064 is
the tie's confidence (`test_tie_confidence_pg.py` holds the server half).

Pure: these read the shipped static assets, as `test_ui_invariants.py`
does. The behaviour was also driven in a real browser on 2026-09-22; what
is pinned here is the shape that behaviour depends on. One check, the
final review's U12 (2026-09-23), executes the endpoint pin under Node and
skips where Node is not installed.
"""
from __future__ import annotations

import inspect
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


def _css() -> str:
    return (STATIC / "app.css").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function's body, closed on the first `}` at column 0."""
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start)]


GRADING_IDS = [f"{p}-{f}" for p in ("node", "edge")
               for f in ("basis", "conf", "rel", "cred")]


# ---------------------------------------------------------------------------
# ux06 grading-prefilled-upward
# ---------------------------------------------------------------------------

def test_no_grading_is_preselected():
    """The four old defaults, by value. `buildPickers` and `resetGrading`
    are where the grading selects are filled, so neither may name one."""
    for fn in ("buildPickers", "resetGrading"):
        body = _fn(fn)
        for default in ("'DIRECT_OBSERVATION'", "'MODERATE'", "'C'", "'3'"):
            assert default not in body, (
                f"{fn} preselects {default}: an ungraded claim would look graded")
    body = _fn("resetGrading")
    for field in ("basis", "conf", "rel", "cred"):
        assert re.search(
            r"optsWithPlaceholder\(\$\(prefix \+ '-" + field + r"'\)", body), (
            f"the {field} select is not built with a 'Choose ...' placeholder")


def test_the_placeholder_is_disabled_and_empty():
    body = _fn("optsWithPlaceholder")
    assert "blank.value = ''" in body and "blank.disabled = true" in body


@pytest.mark.parametrize("element_id", GRADING_IDS)
def test_every_grading_select_is_required(element_id: str):
    m = re.search(r'<select id="' + element_id + r'"[^>]*>', _html())
    assert m, f"#{element_id} is missing from index.html"
    assert "required" in m.group(0), (
        f"#{element_id} is not `required`, so it cannot report :invalid while "
        "unchosen and nothing greys it")


@pytest.mark.parametrize("fn", ["createNode", "createEdge"])
def test_an_ungraded_claim_is_refused_before_anything_is_sent(fn: str):
    body = _fn(fn)
    assert "gradingProblem(" in body, f"{fn} never checks the grading"
    assert body.index("gradingProblem(") < body.index("await api("), (
        f"{fn} sends before it checks the grading")


def test_the_same_grading_offer_is_explicit_and_names_its_values():
    """Batch entry may reuse a grading, but only by a click on a control
    that says what it will apply: never by carrying it over silently."""
    html = _html()
    for prefix in ("node", "edge"):
        assert f'id="{prefix}-same-grading"' in html
        assert f'createForms.lastGrading.{prefix} = gradingOf(\'{prefix}\')' in _fn(
            "createNode" if prefix == "node" else "createEdge")
    body = _fn("renderSameGrading")
    assert "Same grading as the last entry: " in body
    for part in ("last.rel", "last.cred", "last.conf"):
        assert part in body, f"the offer does not name {part}"


def test_an_unchosen_select_reads_as_unset():
    css = _css()
    assert re.search(r"select\.select:invalid\s*\{[^}]*var\(--text-tertiary\)", css)
    assert re.search(r"select\.select:disabled\s*\{[^}]*var\(--text-tertiary\)", css)


# ---------------------------------------------------------------------------
# ux06 edge-type-defaults-to-scam-accusation
# ---------------------------------------------------------------------------

def test_the_type_select_starts_on_a_placeholder_not_the_first_type():
    body = _fn("refreshEdgeTypes")
    assert "'Choose a relationship type'" in body
    assert "blank.disabled = true" in body
    # The shape of the defect: the list rebuilt with nothing selected, so
    # the browser selected its first option.
    assert not re.search(r"opts\(sel,\s*legal", body), (
        "the type list is built without a placeholder again")


def test_a_chosen_type_is_kept_when_legal_and_cleared_aloud_when_not():
    body = _fn("refreshEdgeTypes")
    assert "createForms.wantedType" in body
    assert "legal.some((t) => t.key === wanted)" in body
    assert "createForms.clearedType = wanted" in body
    assert "so it was cleared" in _fn("describeEdgeType")
    assert "createForms.wantedType = $('edge-type').value" in _fn("onEdgeTypeChange")
    assert re.search(r"\$\('edge-type'\)\.addEventListener\('change',\s*onEdgeTypeChange\)",
                     _js())


def test_submitting_without_a_type_is_refused_with_a_reason():
    body = _fn("createEdge")
    assert "Choose a relationship type. None is chosen for you." in body
    assert body.index("if (!edgeType)") < body.index("await api(")


def test_negative_ties_are_grouped_apart():
    js = _js()
    assert "Negative ties" in js
    assert "Math.sign(t.default_sign)" in _fn("refreshEdgeTypes")


# ---------------------------------------------------------------------------
# ux06 edge-endpoint-pickers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("element_id", [
    "edge-src-filter", "edge-dst-filter", "edge-src-count", "edge-dst-count",
    "edge-swap", "edge-need-entities",
])
def test_the_endpoint_controls_exist(element_id: str):
    """Built by concatenation in app.js (`'edge-' + which + '-filter'`), so
    `test_element_ids_exist`'s scan of literal `$('...')` calls cannot see
    them. A typo here would be a filter box that silently does nothing."""
    assert f'id="{element_id}"' in _html()


def test_both_endpoints_open_unchosen_and_filterable():
    body = _fn("buildEndpointSelect")
    assert "'Choose the source entity'" in body
    assert "'Choose the target entity'" in body
    assert "blank.selected = true" in body
    js = _js()
    assert re.search(r"-filter'\)\.addEventListener\('input'", js)
    assert re.search(r"-filter'\)\.addEventListener\('keydown'", js)
    # The palette's matching rule: every word appears in label or type.
    assert "terms.every((t) => hay.includes(t))" in _fn("endpointMatches")


def test_a_filter_never_unchooses_an_entity():
    body = _fn("buildEndpointSelect")
    assert "n.id === keep || endpointMatches(n, terms)" in body


def test_enter_in_a_filter_picks_rather_than_submits():
    body = _fn("onEndpointFilterKey")
    assert "event.preventDefault()" in body


def test_enter_in_an_empty_filter_picks_nothing():
    """Fix-round verifier, 2026-09-22: with the filter cleared, Enter chose
    the first entity of the whole list (amber_heron in NIGHTJAR), an
    endpoint nobody picked. No terms, no pick, and no preventDefault, so
    Enter submits as it does in any other field and createEdge refuses an
    unfinished form with its reason."""
    body = _fn("onEndpointFilterKey")
    guard = "if (!endpointTerms(which).length) return;"
    assert guard in body
    assert body.index(guard) < body.index("event.preventDefault()")
    assert body.index(guard) < body.index("endpointChoices(which)[0]")


def test_a_case_with_fewer_than_two_entities_says_to_add_them():
    """Fix-round verifier, 2026-09-22: the empty OP-WHEATEAR-26 read "0
    entities, grouped by type. Type above to filter", naming the wrong next
    step. Fewer than two entities is said once, beside a way out."""
    body = _fn("buildEndpointSelect")
    assert "This case has no entities yet. " in body
    assert "A relationship joins two, so add them first." in body
    assert body.index("if (total < 2)") < body.index("Type above to filter")
    pickers = _fn("buildEdgePickers")
    assert "show($('edge-need-entities'), !enough)" in pickers
    assert "show($('edge-swap'), enough)" in pickers
    assert re.search(r"\$\('edge-need-entities'\)\.addEventListener\('click'", _js())


def test_the_inspector_hook_chooses_one_end_and_nothing_else():
    """`openLinkFormFrom` is what the inspector's "Link from / to this
    entity" (another group's pane) calls. It must leave the other end, the
    type and the grading to the analyst."""
    body = _fn("openLinkFormFrom")
    assert "buildEndpointSelect(which, nodeId)" in body
    assert "selectTab('add-edge')" in body
    for chosen in ("wantedType =", "resetGrading(", "-conf').value ="):
        assert chosen not in body


def test_the_inspector_hook_offers_an_entity_beyond_the_entity_page():
    """Final review U12, 2026-09-23. The pickers were built from
    `state.nodes`, the newest 1000, while the canvas draws the oldest 800,
    so "Link from this..." on an older entity in a large case opened on
    "Choose the source entity" without a word, and the entity could not be
    chosen in the form at all. The hook now pins the entity first, from
    the sociogram's record or a read under the session's clearance, and
    says so when it cannot."""
    body = _fn("openLinkFormFrom")
    assert body.index("await pinEndpoint(nodeId, token)") < body.index(
        "buildEndpointSelect(which, nodeId)")
    assert "caseChanged(token)" in body
    assert "could not be read" in body, "a failed pin must be said, not blank"
    pin = _fn("pinEndpoint")
    assert "state.gnodes" in pin and "cpath('/nodes/' + nodeId)" in pin
    assert "withSafeLabel(" in pin, "a read label crosses the bidi guard"
    assert "if (!caseChanged(token)) createForms.pinnedEnds.set(" in pin
    # Every picker path reads the pool, not the entity page alone.
    build = _fn("buildEndpointSelect")
    assert "const pool = endpointPool();" in build
    assert "state.nodes" not in build
    assert "endpointPool().filter(" in _fn("endpointChoices")
    for fn in ("refreshEdgeTypes", "onEdgeTypeChange", "createEdge"):
        assert "state.nodes.find(" not in _fn(fn), fn
        assert "endpointNode(" in _fn(fn), fn


def test_a_pinned_end_is_dropped_on_a_switch_and_read_again_on_a_reopen():
    """Pinned records were read under the session that pinned them, and a
    sign-out runs the switch reset, so every reset drops them. A reopen of
    the same case reads a kept end again rather than losing it silently."""
    assert "createForms.pinnedEnds.clear();" in _fn("resetCreateForms")
    pickers = _fn("buildEdgePickers")
    assert "restoreEndpoint(which, kept[which])" in pickers
    assert "!endpointNode(kept[which])" in pickers
    restore = _fn("restoreEndpoint")
    assert "caseChanged(token)" in restore
    assert "could not be read again" in restore


_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)


@pytest.mark.skipif(not NODE, reason="Node is not installed here")
def test_pinning_finds_a_drawn_entity_then_reads_one_then_says_why(tmp_path):
    """Executes the shipped pool and pin functions under Node, with the
    case's lists and the API stubbed."""
    js = _js()

    def source(name: str) -> str:
        start = js.index(f"function {name}(")
        if js[start - 6:start] == "async ":
            start -= 6
        return js[start:js.index("\n}", start) + 2]

    sources = "\n".join(source(name) for name in
                        ("endpointPool", "endpointNode", "pinEndpoint"))
    script = tmp_path / "run.js"
    script.write_text("""
const state = { nodes: [{id: 'new1', label: 'newest', node_type: 'PERSONA'}],
                gnodes: [{id: 'old1', label: 'oldest', node_type: 'PERSONA'}] };
const createForms = { pinnedEnds: new Map() };
let token = 1;
function caseChanged(t) { return t !== token; }
function cpath(s) { return '/cases/c1' + s; }
function withSafeLabel(r) { return Object.assign({}, r, {safe: true}); }
function failureReason(err) { return 'HTTP ' + err.status; }
const reads = [];
async function api(path) {
  reads.push(path);
  if (path.endsWith('/far1')) return {id: 'far1', label: 'far', node_type: 'WALLET'};
  throw {status: 404};
}
""" + sources + """
(async () => {
  const out = {};
  out.inPage = await pinEndpoint('new1', 1);
  out.drawn = await pinEndpoint('old1', 1);
  out.read = await pinEndpoint('far1', 1);
  out.refused = await pinEndpoint('gone1', 1);
  out.pool = endpointPool().map((n) => n.id);
  out.farSafe = endpointNode('far1').safe === true;
  out.reads = reads.slice();
  token = 2;                               // the case changes mid-read
  out.late = await pinEndpoint('far1', 1) === null
    && endpointNode('far1') !== null;      // already pinned: no new read
  createForms.pinnedEnds.clear();
  const p = pinEndpoint('far1', 1); token = 3; await p;
  out.stale = endpointNode('far1');
  console.log(JSON.stringify(out));
})();
""", encoding="utf-8")
    run = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    out = json.loads(run.stdout)
    assert out["inPage"] is None and out["drawn"] is None and out["read"] is None
    assert out["refused"] == "HTTP 404", "the reason reaches the analyst"
    assert out["pool"] == ["new1", "old1", "far1"]
    assert out["farSafe"] is True
    assert out["reads"] == ["/cases/c1/nodes/far1", "/cases/c1/nodes/gone1"], (
        "an entity on the page or on the canvas is not read again")
    assert out["late"] is True
    assert out["stale"] is None, "a reply for a case since left pins nothing"


def test_a_self_loop_is_named_when_the_endpoints_change():
    body = _fn("refreshEdgeTypes")
    assert "src.id === dst.id" in body
    assert "Source and target are the same entity" in body


def test_the_reverse_direction_advice_is_only_given_when_it_helps():
    body = _fn("refreshEdgeTypes")
    assert "legalEdgeTypes(dst.node_type, src.node_type)" in body


# ---------------------------------------------------------------------------
# ux06 edge-confidence-not-stored, client half
# ---------------------------------------------------------------------------

def test_the_link_form_sends_its_confidence_inside_the_assertion_only():
    """The API refuses a top-level `confidence` on POST /edges (it used to
    drop it). The grade goes in `assertion`, which is where 0064 reads it."""
    body = _fn("createEdge")
    payload = body[body.index("json: {"):body.index("});", body.index("json: {"))]
    assert "confidence" not in payload
    assert "assertion: assertion" in payload
    assert "confidence: $(prefix + '-conf').value" in _fn("assertionFrom")


def test_the_service_has_no_second_confidence_for_a_new_edge():
    """Two parameters for one fact disagree: the old `confidence="LOW"`
    default beside the assertion's grade is the whole defect."""
    from noctornal_api.graph import GraphWriteService
    params = inspect.signature(GraphWriteService.create_edge).parameters
    assert "confidence" not in params


# ---------------------------------------------------------------------------
# Case switching
# ---------------------------------------------------------------------------

def _typed_ids() -> list[str]:
    js = _js()
    start = js.index("const CREATE_FORM_TYPED = [")
    return re.findall(r"'([a-z-]+)'", js[start:js.index("];", start)])


def test_the_forms_reset_on_a_case_switch():
    """The registered reset drops the old case's entity lists and messages;
    a DIFFERENT case also drops everything the analyst entered."""
    js = _js()
    assert "onCaseSwitch(resetCreateForms);" in js
    reset = _fn("resetCreateForms")
    assert "clear($(id))" in reset and "setMsg($(id), '')" in reset
    adopt = _fn("adoptCaseInCreateForms")
    assert "createForms.caseId === state.caseId" in adopt
    for part in ("lastGrading", "wantedType", "keptEnds",
                 "for (const id of CREATE_FORM_TYPED) $(id).value = ''"):
        assert part in adopt
    pickers = _fn("buildPickers")
    assert "const same = adoptCaseInCreateForms();" in pickers
    assert (pickers.index("adoptCaseInCreateForms()")
            < pickers.index("resetGrading('node'")), (
        "the grading is rebuilt before the forms know which case they are in")
    for fn in ("createNode", "createEdge"):
        assert "caseChanged(token)" in _fn(fn), (
            f"{fn} does not drop a result that lands after a case switch")


def test_reopening_the_same_case_keeps_what_the_analyst_typed():
    """Fix-round verifier, 2026-09-22: editing a case's title or status
    reopens it (openCase(state.caseId)), which runs every case-switch
    reset, and this one cleared a half-typed label, rationale and
    reference. The reset now leaves the typed fields alone; the decision
    waits for the new case id, and the same id keeps them."""
    reset = _fn("resetCreateForms")
    for field in _typed_ids():
        assert f"'{field}'" not in reset, (
            f"the case-switch reset clears #{field} even for the same case")
    assert "createForms.keptEnds = {" in reset
    pickers = _fn("buildPickers")
    assert "resetGrading('node', same ? gradingOf('node') : null)" in pickers
    assert "resetGrading('edge', same ? gradingOf('edge') : null)" in pickers
    assert "kept ? kept.src : undefined" in _fn("buildEdgePickers")


def test_every_typed_field_named_for_a_case_switch_exists():
    ids = _typed_ids()
    html = _html()
    # The three the verifier saw lost, by name.
    for named in ("node-label", "node-rationale", "node-ref", "edge-rationale",
                  "edge-ref", "edge-src-filter", "edge-dst-filter"):
        assert named in ids
    for element_id in ids:
        assert f'id="{element_id}"' in html, f"#{element_id} is not in index.html"


# ---------------------------------------------------------------------------
# House style: nothing an analyst reads carries an em or en dash
# ---------------------------------------------------------------------------

def test_the_create_forms_carry_no_em_or_en_dash():
    js = _js()
    region = js[js.index("/* ── create forms"):js.index("/* ── command palette")]
    # The region's own header rule is box drawing (U+2500), not a dash.
    assert "\u2014" not in region and "\u2013" not in region
    html = _html()
    panes = html[html.index('<section id="pane-add-node"'):html.index("<!-- INSPECTOR -->")]
    assert "\u2014" not in panes and "\u2013" not in panes
