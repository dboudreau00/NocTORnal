"""The pane an analyst picks while a case opens is kept (2026-10-08).

`openCase` shows the workspace as soon as the record has arrived and then
awaits the graph, the evidence register, the triage queue and the badges,
which on a large case is seconds. The rail is live meanwhile, and a click on
Evidence in that window was undone by the `selectTab('graph')` the open ended
on, so the analyst watched their pane swapped for the Graph. `selectTab` now
counts the choices made, `openCase` reads the count before and after, and it
ends on Graph (and on a deep link's pane) only when nobody chose.

The functions run under Node with their collaborators stubbed (skipped where
Node is not installed): a click during the load, a load nobody touched, a
deep link, a deep link and a click, and a second open that overtakes the first.
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


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8").replace("\r\n", "\n")


def _fn(name: str) -> str:
    js = _js()
    start = js.index(f"function {name}(")
    if js[start - 6:start] == "async ":
        start -= 6
    return js[start:js.index("\n}", start) + 2]


# --- the shape of it, with no Node needed --------------------------------------

def test_selecttab_counts_every_choice_and_nothing_else_does():
    js = _js()
    assert len(re.findall(r"(?m)^let _tabChoices = 0;$", js)) == 1
    select = _fn("selectTab")
    assert select.index("_tabChoices += 1;") < select.index("state.tab = name;")
    assert len(re.findall(r"_tabChoices \+= 1", js)) == 1, "only selectTab counts"


def test_open_case_ends_on_graph_only_when_no_pane_was_chosen_meanwhile():
    body = _fn("openCase")
    snapshot = body.index("const choicesAtOpen = _tabChoices;")
    assert snapshot < body.index("await Promise.all"), (
        "the count is read after the first await: a click during the record's "
        "own fetch would be missed")
    assert "const picked = _tabChoices !== choicesAtOpen;" in body
    assert "if (!picked) selectTab('graph');" in body
    assert "applyDeepLinkTab(picked);" in body
    # No other selectTab in the open: it would count as a choice.
    assert body.count("selectTab(") == 1, "a second selectTab in the open counts as a pick"
    assert "chosenMeanwhile" in _fn("applyDeepLinkTab")


# --- the behaviour, under Node ---------------------------------------------------

HARNESS = """
const calls = [];
const state = { tab: 'graph', caseId: null, cases: [], deepLinkTab: null,
  nodes: [], edges: [], layout: new Map(), view: {}, proj: {}, };
let caseGeneration = 0;
const waiting = [];
function gate() { return new Promise((resolve) => { waiting.push(resolve); }); }
function release() { waiting.splice(0).forEach((resolve) => resolve()); }
const SCENARIO = __SCENARIO__;
const document = { querySelectorAll() { return []; }, querySelector() { return {}; },
  title: '' };
const $ = () => ({ textContent: '', className: '', hidden: false, tabIndex: 0,
  setAttribute() {} });
const noop = () => {};
const show = noop, renderCaseState = noop, showCaseChrome = noop,
  renderHeaderRole = noop, loadLookupProviders = noop, buildPickers = noop,
  loadCaseTags = noop, renderInspector = noop, buildProjectionControls = noop,
  renderProjectionBar = noop, refreshSampleBadge = noop, refreshFeedsBadge = noop,
  connectLive = noop, stopWorkerLayout = noop, applyMetrics = noop,
  hideCaseChrome = noop, runCaseSwitchResets = noop, writeLocation = noop,
  resizeGraph = noop, resizeDensity = noop, resizeHistory = noop,
  loadLatestAnalysis = noop, loadTriageNow = noop, loadApprovals = noop,
  enterAdminPane = noop, clearAdminCreds = noop, clearKeySecret = noop,
  loadCommsPlatforms = () => Promise.resolve(), loadUnverified = noop,
  loadPgpKeys = noop, loadKeyDirectory = noop, loadKeyLookups = noop,
  loadInbox = noop, loadInboxPreferences = noop, loadAch = noop,
  loadAssumptions = noop, caseTitle = () => 'Case', fail = noop;
let selectFeedsSub = null, selectGovSub = null, selectSamplesSub = null,
  selectDeceptionSub = null;
function currentSub() { return null; }
function caseToken() { return caseGeneration; }
function caseChanged(token) { return token !== caseGeneration; }
function loadEvidence(options) {
  calls.push('loadEvidence' + (options && options.pageOnly ? ':page' : ''));
  return Promise.resolve();
}
function loadTriage() { return Promise.resolve(); }
function refreshInboxBadge() { return Promise.resolve(); }
function refreshSociogram() { return Promise.resolve(); }
function loadPresets() { return Promise.resolve(); }
function loadLayout() { return Promise.resolve(); }
function loadCaseGraph() { return gate(); }
async function api(path) {
  if (path.endsWith('/ontology')) return { node_types: [] };
  return { code: 'OP-X', title: 'T', classification: 'AMBER' };
}
const _log = [];
"""

TAIL = """
(async () => {
  const done = [];
  const open = (id) => { caseGeneration += 1; state.caseId = id; return openCase(id); };
  __RUN__
  console.log(JSON.stringify({ tab: state.tab, deepLinkTab: state.deepLinkTab, calls, done }));
})();
"""


def _run(run: str, scenario: dict | None = None) -> dict:
    if not NODE:
        pytest.skip("Node is not installed here")
    js = _js()
    # Absent in the build before the fix, so these scenarios run against it
    # too and fail on what the analyst sees rather than on a missing name.
    found = re.search(r"(?m)^let _tabChoices = 0;$", js)
    declared = found.group(0) if found else ""
    script = HARNESS.replace("__SCENARIO__", json.dumps(scenario or {})) + "\n".join([
        declared, _fn("selectTab"), _fn("applyDeepLinkTab"), _fn("openCase"),
        TAIL.replace("__RUN__", run)])
    proc = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                          encoding="utf-8", timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


# The open waits on the graph; `settle` lets the microtasks run.
SETTLE = "const settle = () => new Promise((r) => setTimeout(r, 20));"


def test_a_click_while_the_case_loads_is_not_taken_back():
    got = _run(f"""{SETTLE}
  const opening = open('c1');
  await settle();
  selectTab('evidence');            // the analyst clicks while the graph loads
  release();
  await opening;
""")
    assert got["tab"] == "evidence", got


def test_an_open_nobody_touched_ends_on_the_graph_as_it_always_did():
    got = _run(f"""{SETTLE}
  state.tab = 'comms';              // left over from the case before
  const opening = open('c1');
  await settle();
  release();
  await opening;
""")
    assert got["tab"] == "graph", got


def test_a_deep_link_is_followed_when_nobody_chose_and_dropped_when_somebody_did():
    untouched = _run(f"""{SETTLE}
  state.deepLinkTab = 'governance';
  const opening = open('c1');
  await settle();
  release();
  await opening;
""")
    assert untouched["tab"] == "governance" and untouched["deepLinkTab"] is None, untouched
    chosen = _run(f"""{SETTLE}
  state.deepLinkTab = 'governance';
  const opening = open('c1');
  await settle();
  selectTab('search');
  release();
  await opening;
""")
    assert chosen["tab"] == "search", chosen
    assert chosen["deepLinkTab"] is None, "the link is spent whether or not it was followed"


def test_a_pick_made_before_a_second_open_does_not_stop_that_open_ending_on_the_graph():
    """The count is per open: a choice made while case A loaded is not a
    choice about case B, which starts from its own count."""
    got = _run(f"""{SETTLE}
  const first = open('a');
  await settle();
  selectTab('evidence');
  const second = open('b');         // overtakes the first
  await settle();
  release();
  await Promise.all([first, second]);
""")
    assert got["tab"] == "graph", got


def test_the_pane_chosen_is_the_one_the_address_and_the_state_hold():
    got = _run(f"""{SETTLE}
  const opening = open('c1');
  await settle();
  selectTab('comms');
  release();
  await opening;
""")
    assert got["tab"] == "comms"
