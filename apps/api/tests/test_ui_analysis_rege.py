"""The Analysis pane's regular-role card: REGE (ROADMAP-REMAINING phase 3,
2026-10-02).

Held to the Roles card's tests (test_ui_analysis_roles.py) point for point,
and behavioural where it matters: the shipped loader, renderer and image
table run under node with the fake DOM of `test_ui_analysis_pane.py`, whose
prelude and extractors this file imports. The rule every loader keeps (a
case token, and a reply for a case left is dropped) is asserted here for
`loadRege`. The server halves are `test_rege.py`, `test_rege_pg.py` and
`test_rege_http_pg.py`.

Pure: no database. The node halves skip when node is not installed.
"""
from __future__ import annotations

import re

from test_ui_analysis_pane import _PRELUDE, _const, _fn, _html, _js, _run, _src
from test_ui_analysis_views import _currency


def _loader() -> str:
    return _PRELUDE + r"""
const renders = [];
function renderRege() { renders.push(JSON.parse(JSON.stringify(state.analyticsRege))); }
const defanged = [];
function safeLabelsDeep(x) { defanged.push(x); return x; }
$('an-rege-roles').value = '4';
$('an-rege-weighting').value = 'presence';
state.analytics = { run_id: 'suite-1' }; state.analyticsQuery = 'preset=all';
""" + _src("analysisFailureText", "loadRege", "onRegeChange")


_LATEST = '/analytics/rege/latest?preset=all&roles=4&weighting=presence'


def test_the_card_reads_the_stored_run_first_and_computes_on_run():
    got = _run(_loader() + r"""
(async () => {
  // Opening the pane on a stored run reads, and never computes.
  loadRege(true); await tick();
  out.firstAsk = calls.map((c) => c.path);
  take('/analytics/rege/latest').reject(new ApiError(404, 'Not found', ''));
  await tick(); await tick();
  out.missing = state.analyticsRege;
  out.computedOnOpen = calls.some((c) => c.path.includes('/analytics/rege?'));
  // A Run reads the stored run, and computes because the graph moved.
  loadRege(false); await tick();
  take('/analytics/rege/latest').resolve({ run_id: 'old', current: false });
  await tick(); await tick();
  take('/analytics/rege?preset=all&roles=4&weighting=presence').resolve(
    { run_id: 'rege-2', current: true, rege: { roles: [] }, nodes: [] });
  await tick(); await tick();
  out.after = state.analyticsRege.run_id;
  out.renders = renders;
  // A stored run that still holds is used as it is.
  loadRege(false); await tick();
  take('/analytics/rege/latest').resolve({ run_id: 'kept', current: true });
  await tick(); await tick();
  out.kept = state.analyticsRege.run_id;
  out.spent = calls.length;
  console.log(JSON.stringify(out));
})();
""")
    assert got["firstAsk"] == ["/cases/case-a" + _LATEST]
    assert got["missing"] == {"missing": True, "roles": 4, "weighting": "presence"}
    assert not got["computedOnOpen"], "opening the pane spent a metered regular-role run"
    assert got["after"] == "rege-2"
    assert {"pending": True, "reading": True, "roles": 4, "weighting": "presence"} \
        in got["renders"]
    assert {"pending": True, "roles": 4, "weighting": "presence"} in got["renders"]
    assert got["kept"] == "kept" and got["spent"] == 0


def test_opening_the_pane_on_a_stale_stored_run_shows_it_and_computes_nothing():
    """The stored run no longer matches the graph: opening the pane still
    shows it, flagged stale, and never computes (a metered run) or reports
    that nothing was stored. Only the 404 case was held before, so reading
    the stored run as missing, or computing over it, passed (2026-10-02)."""
    got = _run(_loader() + r"""
(async () => {
  loadRege(true); await tick();
  out.asked = calls.map((c) => c.path);
  take('/analytics/rege/latest').resolve({ run_id: 'old', current: false,
    rege: { roles: [] }, nodes: [] });
  await tick(); await tick();
  out.shown = state.analyticsRege;
  out.computed = calls.some((c) => c.path.includes('/analytics/rege?'));
  console.log(JSON.stringify(out));
})();
""")
    assert got["shown"]["run_id"] == "old" and got["shown"]["current"] is False
    assert not got["shown"].get("missing"), "a stale stored run was shown as not stored"
    assert not got["computed"], "opening the pane computed over a stale stored run"
    assert got["asked"] == ["/cases/case-a" + _LATEST]


def test_the_run_and_the_stored_read_ask_for_the_card_without_waiting_on_it():
    run = _fn("runAnalysis")
    assert "loadRege(false);" in run and "await loadRege" not in run
    assert run.index("loadConcor(false);") < run.index("loadRege(false);")
    stored = _fn("loadLatestAnalysis")
    assert "loadRege(true);" in stored and "await loadRege" not in stored


def test_a_control_change_fetches_only_this_card():
    got = _run(_loader() + r"""
(async () => {
  $('an-rege-roles').value = '6';
  $('an-rege-weighting').value = 'weight';
  onRegeChange(); await tick();
  out.asked = calls.map((c) => c.path);
  // A value the control cannot hold is read as the default weighting.
  calls.length = 0;
  $('an-rege-weighting').value = 'decayed';
  onRegeChange(); await tick();
  out.odd = calls.map((c) => c.path);
  console.log(JSON.stringify(out));
})();
""")
    assert got["asked"] == ["/cases/case-a/analytics/rege/latest?preset=all&roles=6"
                            "&weighting=weight"]
    assert got["odd"] == ["/cases/case-a/analytics/rege/latest?preset=all&roles=6"
                          "&weighting=presence"]
    js = _js()
    assert "$('an-rege-roles').addEventListener('change', onRegeChange);" in js
    assert "$('an-rege-weighting').addEventListener('change', onRegeChange);" in js
    wire = _fn("onRegeChange")
    assert "loadRege(false)" in wire and "blankAnalytics" not in wire
    html = _html()
    assert '<select id="an-rege-roles" class="select">' in html
    assert '<option value="4" selected>Up to 4 roles</option>' in html
    assert '<option value="8">Up to 8 roles</option>' in html
    assert '<select id="an-rege-weighting" class="select">' in html
    assert '<option value="presence" selected>As present or absent</option>' in html
    assert '<option value="weight">By weight</option>' in html


def test_a_late_reply_never_draws_over_the_controls_on_screen():
    got = _run(_loader() + r"""
(async () => {
  loadRege(false); await tick();
  const four = take('/analytics/rege/latest?preset=all&roles=4');
  $('an-rege-roles').value = '2';
  onRegeChange(); await tick();
  take('/analytics/rege/latest?preset=all&roles=2').resolve({ run_id: 'r2', current: true,
    rege: { roles_asked: 2 } });
  await tick(); await tick();
  four.resolve({ run_id: 'r4', current: true, rege: { roles_asked: 4 } });
  await tick(); await tick();
  out.shown = state.analyticsRege.run_id;
  console.log(JSON.stringify(out));
})();
""")
    assert got["shown"] == "r2", "the reply for the old number of roles drew over the new one"


def test_loadRege_takes_a_case_token_and_drops_a_reply_for_a_case_left():
    got = _run(_loader() + r"""
(async () => {
  loadRege(false); await tick();
  const ask = take('/analytics/rege/latest');
  state.caseSeq += 1;                              // the analyst left the case
  ask.resolve({ run_id: 'other-case', current: true });
  await tick(); await tick();
  out.shown = state.analyticsRege;
  out.more = calls.length;
  console.log(JSON.stringify(out));
})();
""")
    assert got["shown"] == {"pending": True, "reading": True, "roles": 4,
                            "weighting": "presence"}
    assert got["more"] == 0
    body = _fn("loadRege")
    assert "const token = caseToken();" in body and "caseChanged(token)" in body


def test_the_case_switch_and_the_blank_clear_the_card():
    js = _js()
    switch = js[js.index("onCaseSwitch(() => {\n  blankAnalytics(AN_EMPTY_TEXT);"):]
    switch = switch[:switch.index("\n});")]
    assert "'an-rege'" in switch
    blank = _fn("blankAnalytics")
    assert "state.analyticsRege = null;" in blank
    assert "state.analyticsRegeAll = {};" in blank


def test_the_payload_goes_through_safeLabelsDeep():
    got = _run(_loader() + r"""
(async () => {
  loadRege(false); await tick();
  take('/analytics/rege/latest').resolve({ run_id: 'r', current: true,
    rege: { roles: [] }, nodes: [] });
  await tick(); await tick();
  out.defanged = defanged.some((x) => x && x.run_id === 'r');
  console.log(JSON.stringify(out));
})();
""")
    assert got["defanged"]
    assert "state.analyticsRege = safeLabelsDeep(found);" in _fn("loadRege")


def test_a_throttle_on_its_own_bucket_is_worded_as_role_analysis():
    got = _run(_PRELUDE + _src("analysisFailureText") + r"""
out.text = analysisFailureText(new ApiError(429, 'Too many requests',
  "rate limit 'analytics.rege' exceeded; retry in 8s"), 'fallback');
console.log(JSON.stringify(out));
""")
    assert got["text"] == ("Role analysis is briefly throttled: it has a budget of its own, "
                           "spent by each run and each check with it. Try again in 8 "
                           "seconds.")


# --------------------------------------------------------------------------
# The card
# --------------------------------------------------------------------------

_CARD_FNS = ("andList", "typeName", "ageText", "actorButton", "graphButton", "pairsWithin",
             "pairKey", "leftOutParts", "reviewScopeText", "regeCutText", "regeImageTable",
             "renderRege")


def _card() -> str:
    return _PRELUDE + r"""
state.nodeTypeMeta = new Map([['FORUM', { display_name: 'Forum' }]]);
const shown = [];
function showSetOnGraph(spec) { shown.push(spec); }
function selectTab() {} function selectNode() {} function renderFocusFlag() {}
function loadRege() {}
""" + _src(*_CARD_FNS) + r"""
const member = (k) => ({ id: 'n' + k, label: 'E' + k, node_type: 'IDENTITY' });
function regular(over, top) {
  return { run_id: 'rege-1', current: true, computed_at: '2026-10-02T10:00:00Z',
    nodes: [1, 2, 3].map((k) => ({ ...member(k), role: k < 3 ? 1 : 2, block_index: k < 3 ? 0 : 1 })),
    ...(top || {}),
    rege: { roles_asked: 4, roles_found: 2, weighting: 'presence',
      roles: [
        { role: 1, block_index: 0, size: 2, members: [member(1), member(2)], cohesion: 0.95,
          least_alike: 0.95 },
        { role: 2, block_index: 1, size: 1, members: [member(3)], cohesion: null,
          least_alike: null }],
      cut: { held_at: 0.95, next_merge: 0.31, fewer_than_asked: true },
      relations: [{ key: 'positive', label: 'positive ties', ties: 3 }],
      density: { positive: [[1.0, 0.5], [0.0, null]] },
      image: { positive: [[1, 1], [0, 0]] }, regular: { positive: [[1, 0], [0, 0]] },
      alpha: { positive: 0.5 }, rounds: 2, max_rounds: 3, converged: true,
      no_ties: { count: 0 }, profile_only: { count: 0, types: [] }, derived_ties: false,
      weightless_ties: 0, unaccepted_ties: 0, reading: 'R.', method: 'M.',
      limits: ['L1.', 'L2.'], ...(over || {}) } };
}
function paint(r) { state.analyticsRege = r; renderRege(); return text($('an-rege')); }
"""


def test_the_head_says_how_many_roles_where_the_cut_fell_and_why_fewer():
    got = _run(_card() + r"""
out.normal = paint(regular());
out.one = paint(regular({ roles_found: 1, roles: [{ role: 1, block_index: 0, size: 3,
  members: [member(1), member(2), member(3)], cohesion: 1, least_alike: 1 }],
  cut: { held_at: 1, next_merge: null, fewer_than_asked: true } }));
out.apart = paint(regular({ cut: { held_at: null, next_merge: 0.4, fewer_than_asked: false } }));
out.unsettled = paint(regular({ converged: false, rounds: 3 }));
console.log(JSON.stringify(out));
""")
    assert ("REGE placed 3 entities with ties in 2 roles, of the 4 asked for. Members were "
            "joined down to a similarity of 0.95, where 1 is alike in every tie; the closest "
            "two roles left apart are 0.31 alike.") in got["normal"]
    assert ("Fewer roles than asked: entities alike at the level of the cut are never "
            "split to make up the number.") in got["normal"]
    assert "Every entity with a tie is in one role." in got["one"]
    assert "regular equivalence finds nearly every entity alike" in got["one"]
    assert "Fewer roles than asked" not in got["one"]
    assert ("No two entities were alike enough to share a role; the closest two are "
            "0.40 alike") in got["apart"]
    assert "REGE stopped after 3 rounds while similarities were still moving" \
        in got["unsettled"]
    assert "stopped after" not in got["normal"]
    assert "From the regular-role run of 2026-10-02 10:00 UTC" in got["normal"]


def test_each_role_names_its_members_and_how_alike_they_are():
    got = _run(_card() + r"""
out.card = paint(regular());
console.log(JSON.stringify(out));
""")
    card = got["card"]
    assert "Role 1 (2): E1, E2" in card and "Role 2 (1): E3" in card
    assert "Members are on average 0.95 alike; the least alike two, 0.95." in card
    assert "A role of one: no other entity was alike enough to join it." in card
    # Every limit the server states is printed, under its heading.
    assert "What these roles can and cannot say" in card
    assert "L1." in card and "L2." in card and "R." in card and "M." in card


def test_the_weighting_derived_ties_and_review_state_are_each_said():
    got = _run(_card() + r"""
out.weight = paint(regular({ weighting: 'weight', weightless_ties: 2, derived_ties: true }));
out.presence = paint(regular({ derived_ties: true }));
out.unaccepted = paint(regular({ unaccepted_ties: 1 }));
out.accepted = paint(regular({ unaccepted_ties: 0 }, { review_scope: { scope: 'accepted',
  left_out: { ties: { proposed: 2 } } } }));
out.plain = paint(regular());
console.log(JSON.stringify(out));
""")
    assert ("Ties count by weight here, so a weak tie only partly matches a strong one. "
            "Counted as present or absent, the roles can differ.") in got["weight"]
    assert "2 ties carry no positive weight and count as absent." in got["weight"]
    assert "a derived tie counts here at its venue weighting" in got["weight"]
    assert "a derived tie counts here as a whole tie" in got["presence"]
    assert ("1 tie in this view is not accepted by a reviewer and shapes these roles like "
            "any other. Choose accepted ties only to see roles that rest on reviewed ties "
            "alone.") in got["unaccepted"]
    assert "Computed over accepted ties only. Left out: 2 unreviewed proposals." \
        in got["accepted"]
    for word in ("Ties count by weight", "derived tie", "not accepted by a reviewer"):
        assert word not in got["plain"], word


def test_a_role_can_be_shown_on_the_graph_and_the_flag_names_the_run():
    got = _run(_card() + _src("setFocusSource") + r"""
state.gedges = [{ src_node_id: 'n1', dst_node_id: 'n2' }, { src_node_id: 'n2', dst_node_id: 'n3' }];
paint(regular());
const buttons = $('an-rege').querySelectorAll('button')
  .filter((b) => b.textContent === 'Show on graph');
buttons[0].click();
const spec = shown[0];
out.spec = { label: spec.label, fromRege: spec.fromRege, lit: [...spec.lit],
             pairs: [...spec.pairs], note: spec.note };
const focus = { fromRege: true, runId: 'rege-1' };
out.fresh = setFocusSource(focus);
state.analyticsRege.current = false;
out.stale = setFocusSource(focus);
state.analyticsRege = null;
out.gone = setFocusSource(focus);
console.log(JSON.stringify(out));
""")
    spec = got["spec"]
    assert spec["label"] == "regular role 1" and spec["fromRege"] is True
    assert spec["lit"] == ["n1", "n2"] and spec["pairs"] == ["n1|n2"]
    assert "a hypothesis about how they sit in this view" in spec["note"]
    assert got["fresh"] == "from the Analysis pane"
    assert got["stale"] == "from an analysis run the graph has changed since"
    assert got["gone"] == "from an analysis run no longer on the Analysis pane"
    assert "fromRege: !!spec.fromRege" in _fn("showSetOnGraph")


def test_the_image_marks_tied_and_regular_blocks_in_words_and_classes():
    got = _run(_card() + r"""
paint(regular());
const cells = [];
function walkAll(n) { for (const c of n.children || []) { if (c.tag === 'td') cells.push(c);
  walkAll(c); } }
walkAll($('an-rege'));
const captions = [], heads = [];
function caps(n) { for (const c of n.children || []) {
  if (c.tag === 'caption') captions.push(c.textContent);
  if (c.tag === 'th') heads.push(c.textContent); caps(c); } }
caps($('an-rege'));
out.cells = cells.map((c) => ({ text: text(c), shaded: [...c.classList.s], cls: c.className }));
out.captions = captions; out.heads = heads;
console.log(JSON.stringify(out));
""")
    texts = [c["text"] for c in got["cells"]]
    assert texts == ["1.000 tied regular", "0.500 tied", "0.000", "not defined"], texts
    shaded = [c for c in got["cells"] if "on-positive" in c["shaded"]]
    assert [c["text"] for c in shaded] == ["1.000 tied regular", "0.500 tied"]
    assert got["cells"][3]["cls"] == "absent"
    assert got["captions"] == [
        "Density of positive ties from each role (rows) to each role (columns). Blocks "
        "marked tied are at least 0.500, the density of positive ties among these "
        "entities; blocks marked regular have such a tie from every member of the row role "
        "and to every member of the column role."]
    assert got["heads"][:3] == ["From / to", "Role 1", "Role 2"]
    for name in ("renderRege", "regeImageTable", "regeCutText"):
        assert ".style" not in _fn(name) and "style=" not in _fn(name)


def test_the_currency_check_asks_for_the_regular_role_run_too():
    got = _run(_currency() + r"""
drawn.rege = [];
function renderRege() { drawn.rege.push(state.analyticsRege && state.analyticsRege.current); }
(async () => {
  onScreen('preset=all');
  state.analyticsRege = { run_id: 'rege-1', current: true };
  analyticsAfterGraphRefresh(); await tick();
  out.asked = calls.map((c) => c.path);
  take('/analytics/currency?').resolve({ runs: [{ run_id: 'run-1', current: true },
    { run_id: 'kpp-1', current: true }, { run_id: 'roles-1', current: true },
    { run_id: 'rege-1', current: false }] });
  await tick(); await tick();
  out.rege = state.analyticsRege.current; out.drawn = drawn.rege;
  console.log(JSON.stringify(out));
})();
""")
    assert got["asked"] == ["/cases/case-a/analytics/currency?preset=all&run_id=run-1"
                            "&run_id=kpp-1&run_id=roles-1&run_id=rege-1"]
    assert got["rege"] is False and got["drawn"] == [False]
    body = _fn("checkAnalysisCurrency")
    assert "if (asked(regular)) q.append('run_id', regular.run_id);" in body
    assert "if (asked(regular) && state.analyticsRege === regular) {" in body


def test_the_inspector_names_the_regular_role_when_the_run_placed_the_entity():
    got = _run(_PRELUDE + r"""
function communityNo() { return null; }
function selectTab() {}
""" + _src("renderInspectorAnalysis") + r"""
state.analytics = { node_count: 3, nodes: [{ id: 'n1', betweenness_rank: 1,
  constraint: null }] };
state.analyticsRege = { nodes: [{ id: 'n1', role: 2 }] };
renderInspectorAnalysis('n1');
out.placed = text($('insp-an-brief'));
state.analyticsRege = { error: 'throttled' };
renderInspectorAnalysis('n1');
out.failed = text($('insp-an-brief'));
console.log(JSON.stringify(out));
""")
    assert "Role 2 by regular equivalence." in got["placed"]
    assert "regular equivalence" not in got["failed"]


def test_the_copy_names_no_actor_says_hypothesis_and_obeys_the_copy_rules():
    body = _fn("renderRege") + _fn("regeImageTable") + _fn("regeCutText") + _fn("loadRege")
    strings = re.findall(r"'(?:[^'\\\n]|\\.)*'", body)
    for s in strings:
        assert not re.search(r"\bactors?\b", s, flags=re.I), s
        for bad in ("—", "–", " -- ", "(s)"):
            assert bad not in s, s
    assert "a hypothesis about how they sit in" in _fn("renderRege")
    html = _html()
    assert ('<h3 class="h3">Regular roles: the same kinds of ties to the same kinds of '
            'others</h3>') in html
    assert html.index('id="an-concor"') < html.index('id="an-rege"') \
        < html.index('id="an-balance"')
    assert "'Finding regular roles...'" in body and "'Looking for stored regular roles...'" \
        in body
    pane = html[html.index('id="pane-analytics"'):]
    pane = pane[:pane.index("</section>")]
    assert "style=" not in pane
    assert _const("AN_PROJECTION_CHANGED")
