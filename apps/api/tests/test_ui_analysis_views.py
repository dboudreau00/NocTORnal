"""The Analysis pane's projection options (2026-09-24): the accepted-ties
scope (L3) and venues projected to entities (F2).

Behavioural where it matters: the shipped functions run under node with the
fake DOM of `test_ui_analysis_pane.py`, whose prelude and extractors this
file imports rather than copies. Static checks hold the wiring the harness
does not run. The server halves are `test_review_scope*.py`,
`test_affiliation.py`, `test_one_mode_*.py` and
`test_analysis_options_http_pg.py`.

Pure: no database. The node halves skip when node is not installed.
"""
from __future__ import annotations

import re

from test_ui_analysis_pane import APP_CSS, _PRELUDE, _const, _fn, _html, _js, _run, _src

_VIEW_FNS = ("andList", "projQuery", "anQuery", "leftOutParts", "reviewScopeText",
             "oneModeFamilies", "derivedTotal", "oneModeText", "oneModeFlags",
             "trendKey", "edgeTypeName", "typeName")


def _views() -> str:
    return (_PRELUDE + r"""
state.ontology = { edge_types: [{ key: 'CONTROLS', display_name: 'Controls' }] };
state.nodeTypeMeta = new Map([['FORUM', { display_name: 'Forum' }],
                              ['WALLET', { display_name: 'Wallet' }]]);
function setDefaults() {
  $('an-decay').value = ''; $('an-ties').value = 'all'; $('an-om-max').value = '50';
  $('an-om-forum').checked = false; $('an-om-wallet').checked = false;
}
setDefaults();
""" + _const("AN_ONE_MODE") + "\n" + _src(*_VIEW_FNS))


# ---------------------------------------------------------------------------
# L3: the Ties control
# ---------------------------------------------------------------------------

def test_the_ties_control_reaches_the_query_only_when_not_default():
    got = _run(_views() + r"""
out.plain = anQuery().toString();
$('an-ties').value = 'accepted';
out.accepted = anQuery().toString();
console.log(JSON.stringify(out));
""")
    # The default query string is exactly what it was, so every stored
    # projection name and the query a run is remembered under hold.
    assert got["plain"] == "preset=all&include_inferred=true&min_confidence=LOW"
    assert got["accepted"] == got["plain"] + "&review_scope=accepted"


def _blanking_loop() -> str:
    js = _js()
    m = re.search(r"for \(const id of \[([^\]]*)\]\) \{\n\s*\$\(id\)\.addEventListener"
                  r"\('change', \(\) => \{\n\s*blankAnalytics\('Parameters changed\. "
                  r"Run the analysis again\.'\);", js)
    assert m, "the projection options are not wired to blankAnalytics"
    return m.group(1)


def test_changing_the_ties_control_blanks_the_pane_through_blankAnalytics():
    assert "'an-ties'" in _blanking_loop()
    html = _html()
    assert '<select id="an-ties" class="select">' in html
    assert '<option value="all" selected>All ties</option>' in html
    assert '<option value="accepted">Accepted ties only</option>' in html


def test_the_trend_never_joins_runs_of_different_review_scopes():
    got = _run(_views() + r"""
const base = { min_confidence: 'LOW', include_inferred: false };
out.plain = trendKey('all', base);
out.explicit = trendKey('all', { ...base, review_scope: 'all' });
out.accepted = trendKey('all', { ...base, review_scope: 'accepted' });
console.log(JSON.stringify(out));
""")
    # A default history point (describe() omits the scope) joins a default run.
    assert got["plain"] == got["explicit"]
    assert got["accepted"] != got["plain"]


def test_the_left_out_counts_are_said_in_words():
    got = _run(_views() + r"""
out.one = reviewScopeText({ scope: 'accepted', left_out: { ties: { proposed: 1,
  disputed: 1, rejected: 1, superseded: 1, other: 1 } } });
out.many = reviewScopeText({ scope: 'accepted', left_out: { ties: { proposed: 3,
  disputed: 2, rejected: 0, superseded: 4, other: 0 },
  affiliations: { proposed: 2, disputed: 0, rejected: 0, superseded: 0, other: 1 } } });
out.none = reviewScopeText({ scope: 'accepted', left_out: { ties: { proposed: 0,
  disputed: 0, rejected: 0, superseded: 0, other: 0 } } });
console.log(JSON.stringify(out));
""")
    assert got["one"] == (
        "Computed over accepted ties only. Left out: 1 unreviewed proposal, 1 disputed "
        "tie, 1 rejected tie, 1 superseded tie and 1 tie in another review state. These "
        "numbers describe what reviewers have accepted, not everything the case holds.")
    assert "3 unreviewed proposals, 2 disputed ties and 4 superseded ties." in got["many"]
    assert got["many"].endswith("Affiliations left out before projecting: 2 unreviewed "
                                "proposals and 1 affiliation in another review state.")
    assert got["none"] == ("Computed over accepted ties only. Every tie in this view is "
                           "accepted, so nothing was left out.")
    for text in got.values():
        assert "NaN" not in text and "undefined" not in text


def test_the_scope_is_said_on_the_projection_line_the_flags_and_the_history():
    assert "(p.review_scope === 'accepted' ? ' | accepted ties only' : '')" in _fn(
        "renderAnalytics")
    flags = _fn("renderAnalyticsFlags")
    assert "flags.push(['note', reviewScopeText(a.review_scope)]);" in flags
    # The coverage flag's own literal is kept.
    assert "rc.proposed || rc.disputed || rc.rejected ? 'warn' : 'note'" in flags
    assert "bits.push('accepted ties only')" in _fn("histRow")
    assert "review_scope: p.review_scope, one_mode: p.one_mode" in _fn("shownTrendKey")


# ---------------------------------------------------------------------------
# F2: venues projected to entities
# ---------------------------------------------------------------------------

def test_the_one_mode_controls_reach_the_query_only_when_set():
    got = _run(_views() + r"""
const plain = anQuery().toString();
$('an-om-max').value = '25';
out.sizeAlone = anQuery().toString() === plain;
$('an-om-wallet').checked = true;
out.wallet = anQuery().toString().slice(plain.length);
$('an-om-forum').checked = true;
out.both = anQuery().toString().slice(plain.length);
$('an-om-max').value = '50';
out.defaultSize = anQuery().toString().slice(plain.length);
console.log(JSON.stringify(out));
""")
    assert got["sizeAlone"], "a size with no family projected changed the query"
    assert got["wallet"] == "&one_mode=wallet&max_venue_size=25"
    # One repeated parameter per family, forum first whatever was ticked first.
    assert got["both"] == "&one_mode=forum&one_mode=wallet&max_venue_size=25"
    assert got["defaultSize"] == "&one_mode=forum&one_mode=wallet"


def test_changing_a_one_mode_control_blanks_the_pane():
    ids = _blanking_loop()
    for control in ("'an-om-forum'", "'an-om-wallet'", "'an-om-max'"):
        assert control in ids
    html = _html()
    for control in ('id="an-om-forum" type="checkbox"', 'id="an-om-wallet" type="checkbox"',
                    '<select id="an-om-max" class="select">',
                    '<option value="50" selected>50 entities</option>'):
        assert control in html


def test_the_trend_never_joins_one_mode_runs_of_other_families_weighting_size_or_min_shared():
    got = _run(_views() + r"""
const om = { families: ['forum'], weighting: 'NEWMAN', max_venue_size: 50, min_shared: 1 };
const base = { min_confidence: 'LOW', include_inferred: false };
const key = (o) => trendKey('all', { ...base, one_mode: o });
out.keys = [key(null), key(om), key({ ...om, families: ['forum', 'wallet'] }),
  key({ ...om, weighting: 'COUNT' }), key({ ...om, max_venue_size: 25 }),
  key({ ...om, min_shared: 2 })];
out.same = key(om) === key({ ...om });
console.log(JSON.stringify(out));
""")
    assert len(set(got["keys"])) == len(got["keys"]), got["keys"]
    assert got["same"]


_EVERY_COUNTER = r"""
const cov = (n) => ({ families: ['forum', 'wallet'], max_venue_size: 50,
  oversized: [{ label: 'Big board', size: 60, size_basis: 'case_graph' },
              { label: 'Market', size: 300, size_basis: 'recorded' }],
  oversized_total: n === 1 ? 2 : 9,
  pairs_same_identity: n, pairs_identity_disputed: n, pairs_not_contemporaneous: n,
  pairs_below_min_shared: n, flow_legs_not_contemporaneous: n,
  transactions_unattributed: n, transactions_partly_unattributed: n,
  self_transfers: n, flow_already_paid: n, flow_legs_through_oversized_wallets: n,
  paid_legs_unattributed: n, edges_dropped_with_venues: { CONTROLS: n },
  venues_without_ties: { FORUM: n }, members_not_drawing: { confidence: n, review: 0 },
  derived_ties: { forum: n, wallet_control: 0, wallet_flow: n },
  size_note: 'A venue size note.' });
"""


def test_the_exclusions_are_warned_not_dropped():
    got = _run(_views() + _EVERY_COUNTER + r"""
out.one = oneModeFlags(cov(1));
out.two = oneModeFlags(cov(2));
out.zero = oneModeFlags({ ...cov(0), oversized: [], oversized_total: 0 });
console.log(JSON.stringify(out));
""")
    one = [text for _kind, text in got["one"]]
    # Oversized, eleven counters, the dropped ties, the venues without ties
    # and the confidence floor: a line each.
    assert len(one) == 15, one
    assert one[0] == ("Left out as larger than 50 entities: Big board (60), Market "
                      "(300 recorded).")
    assert "1 pair sharing a venue was not tied, because the two are recorded as one " \
           "identity." in one
    assert "1 pair linked only by a disputed or rejected identity claim keeps its " \
           "derived tie." in one
    assert "1 transaction with no recorded controller on either side draws no tie." in one
    assert "Ties to the projected venues left the view with them: 1 controls tie." in one
    assert "1 projected venue (Forum) draws no tie: one member, every pair excluded, " \
           "or no payment with a recorded controller." in one
    assert "1 membership below the confidence floor counts toward venue sizes but " \
           "draws no tie." in one
    two = [text for _kind, text in got["two"]]
    assert two[0].endswith("Market (300 recorded), and 7 more.")
    assert "2 pairs sharing a venue were not tied, because the two are recorded as " \
           "one identity." in two
    assert "2 transactions with no recorded controller on either side draw no tie." in two
    assert "2 memberships below the confidence floor count toward venue sizes but " \
           "draw no tie." in two
    # The counts are warned, the two quiet facts noted.
    assert {kind for kind, _t in got["one"]} == {"warn", "note"}
    assert got["zero"] == [], "a zero counter still printed a line"


def test_oversized_venue_names_go_through_safeLabelsDeep():
    got = _run(_views() + _const("_DECEPTIVE") + "\n" + _const("_LABEL_KEYS") + "\n"
               + _fn("visibleText") + "\n" + _fn("safeLabelsDeep") + r"""
const hostile = { one_mode: { max_venue_size: 50, oversized_total: 1,
  oversized: [{ label: 'ev\u202eil', size: 60, size_basis: 'case_graph' }] } };
// The shipped de-fanger, declared after the prelude's stub, is the one called.
const safe = safeLabelsDeep(hostile);
out.flag = oneModeFlags(safe.one_mode)[0][1];
console.log(JSON.stringify(out));
""")
    assert "\u202e" not in got["flag"]
    assert "U+202E" in got["flag"]
    # Every path that draws a one-mode payload de-fangs it first.
    assert "state.analytics = safeLabelsDeep(suite);" in _fn("runAnalysis")
    assert "state.analytics = safeLabelsDeep(suite);" in _fn("loadLatestAnalysis")


def test_the_projection_line_never_calls_derived_ties_left_out():
    got = _run(_views() + _EVERY_COUNTER + r"""
out.excluded = oneModeText(cov(1), false);
out.included = oneModeText(cov(2), true);
console.log(JSON.stringify(out));
""")
    assert got["excluded"].startswith(
        "Projected to entities: forums and wallets. Derived here: 1 tie from shared "
        "forums and 1 tie from money moving between wallets. These ties are derived, not "
        "observed, and count here although stored inferred ties are left out. ")
    assert got["excluded"].endswith("A venue size note.")
    assert "count here as inferred ties do." in got["included"]
    line = _fn("renderAnalytics")
    assert "' projected to entities: '" in line
    assert "', although stored inferred ties are left out'" in line
    assert "derived ties left out" not in _js()
    # viewWords is the Graph pane's helper and is called as it was.
    assert "viewWords(p)" in line


def test_the_help_says_conversations_are_projected_in_the_comms_pane():
    html = _html()
    body = html[html.index('<details id="an-onemode" class="an-onemode">'):]
    body = body[:body.index("</details>")]
    assert "<summary>Project venues to entities</summary>" in body
    text = re.sub(r"\s+", " ", body)
    assert ("Conversations are not projected here: the Comms pane's co-participation "
            "view does that, with its protections for third parties.") in text
    assert "These ties are derived, not observed." in text
    assert "conversation" not in _const("AN_ONE_MODE").lower()


def _currency() -> str:
    return _PRELUDE + r"""
function anQuery() { const q = new URLSearchParams({ preset: 'all' });
  if (state.om) q.append('one_mode', 'forum'); return q; }
function syncAnalysisSizeOptions() {}
const drawn = { kpp: [], roles: [] };
function renderKeyPlayer() { drawn.kpp.push(state.analyticsKpp && state.analyticsKpp.current); }
function renderConcor() { drawn.roles.push(state.analyticsConcor && state.analyticsConcor.current); }
const timers = [];
function setTimeout(fn, ms) { timers.push({ fn, ms }); return timers.length; }
function clearTimeout() {}
""" + _const("AN_PROJECTION_CHANGED") + "\n" + _const("AN_ONE_MODE_CHECK_MS") + "\n" + _src(
        "analysisFailureText", "blankAnalytics", "analyticsAfterGraphRefresh",
        "checkAnalysisCurrency", "checkOneModeCurrencyLater", "renderAnalyticsFlags",
        "reviewCoverageText", "decayWords", "andList", "leftOutParts",
        "reviewScopeText", "oneModeFamilies", "oneModeText", "oneModeFlags") \
        + _const("AN_ONE_MODE") + r"""
const checkAnalysisCurrencySoon = () => { checkAnalysisCurrency(); };
function onScreen(q) {
  state.analytics = { run_id: 'run-1', review_coverage: { ties: 4, proposed: 0,
    accepted: 4, rejected: 0, evidenced: 4, inferred: 0 } };
  state.analyticsQuery = q;
  state.analyticsCurrency = { current: true, checkedAt: '2026-09-23T10:00:00Z' };
  state.analyticsKpp = { run_id: 'kpp-1', current: true };
  state.analyticsConcor = { run_id: 'roles-1', current: true };
}
"""


def test_the_currency_check_asks_once_for_every_run_on_screen():
    got = _run(_currency() + r"""
(async () => {
  onScreen('preset=all');
  analyticsAfterGraphRefresh(); await tick();
  out.asked = calls.map((c) => c.path);
  take('/analytics/currency?preset=all&run_id=run-1&run_id=kpp-1&run_id=roles-1')
    .resolve({ runs: [{ run_id: 'run-1', current: true }, { run_id: 'kpp-1', current: false },
                      { run_id: 'roles-1', current: false }] });
  await tick(); await tick();
  out.suite = state.analyticsCurrency.current;
  out.kpp = state.analyticsKpp.current; out.roles = state.analyticsConcor.current;
  out.drawn = JSON.parse(JSON.stringify(drawn));
  // A key-player size changed while the check was out started its own load:
  // the verdict for the old card is not written onto the new one.
  analyticsAfterGraphRefresh(); await tick();
  const ask = take('/analytics/currency?');
  const fresh = { pending: true, n: 4 };
  state.analyticsKpp = fresh;
  ask.resolve({ runs: [{ run_id: 'run-1', current: true },
                       { run_id: 'kpp-1', current: true },
                       { run_id: 'roles-1', current: true }] });
  await tick(); await tick();
  out.fresh = state.analyticsKpp;
  out.rolesAfter = state.analyticsConcor.current;
  console.log(JSON.stringify(out));
})();
""")
    assert len(got["asked"]) == 1, got["asked"]
    assert got["suite"] is True and got["kpp"] is False and got["roles"] is False
    assert got["drawn"]["kpp"] == [False] and got["drawn"]["roles"] == [False]
    assert got["fresh"] == {"pending": True, "n": 4}
    assert got["rolesAfter"] is True
    # The single-run route is no longer what the pane asks.
    assert "/current?" not in _fn("checkAnalysisCurrency")


def test_with_venues_projected_background_checks_are_held_to_one_in_thirty_seconds():
    got = _run(_currency() + r"""
(async () => {
  state.om = true;
  onScreen('preset=all&one_mode=forum');
  state.analyticsOneModeCheckAt = Date.now();
  analyticsAfterGraphRefresh(); analyticsAfterGraphRefresh(); analyticsAfterGraphRefresh();
  await tick();
  out.beforeTimer = calls.length;
  out.timers = timers.map((t) => t.ms);
  timers[0].fn(); await tick();
  out.afterTimer = calls.map((c) => c.path);
  console.log(JSON.stringify(out));
})();
""")
    assert got["beforeTimer"] == 0, "a one-mode check was spent on every refresh"
    assert len(got["timers"]) == 1 and 29000 <= got["timers"][0] <= 30000, got["timers"]
    assert got["afterTimer"] == [
        "/cases/case-a/analytics/currency?preset=all&one_mode=forum&run_id=run-1"
        "&run_id=kpp-1&run_id=roles-1"]


def test_a_set_shown_from_a_one_mode_run_says_the_graph_draws_the_venues():
    got = _run(_PRELUDE + r"""
function selectTab() {} function applySetFocus() {} function renderProjectionBar() {}
""" + _const("AN_ONE_MODE") + "\n" + _src("andList", "oneModeFamilies", "showSetOnGraph") + r"""
state.analytics = { run_id: 'r', one_mode: { families: ['forum', 'wallet'] } };
showSetOnGraph({ label: 'cluster 1', note: 'Cluster 1 of the last run.', lit: new Set() });
out.projected = state.focus.note;
state.analytics = { run_id: 'r' };
showSetOnGraph({ label: 'cluster 1', note: 'Cluster 1 of the last run.', lit: new Set() });
out.plain = state.focus.note;
console.log(JSON.stringify(out));
""")
    assert got["projected"] == ("Cluster 1 of the last run. The ties that grouped them run "
                                "through forums or wallets, which the graph draws as "
                                "recorded.")
    assert got["plain"] == "Cluster 1 of the last run."


def test_no_inline_style_and_only_tokens_in_the_new_css():
    html = _html()
    pane = html[html.index('id="pane-analytics"'):]
    pane = pane[:pane.index("</section>")]
    assert "style=" not in pane
    css = APP_CSS.read_text(encoding="utf-8")
    rules = re.findall(r"^\.an-(?:onemode|image)[^{]*\{[^}]*\}", css, flags=re.M)
    assert len(rules) >= 8, rules
    for rule in rules:
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(", rule), rule
    # Next to the other .an-* rules, never at the end of the file.
    assert css.index(".an-onemode {") < css.index("the responsive story")
    for name in ("renderConcor", "concorImageTable", "oneModeFlags", "oneModeText",
                 "reviewScopeText"):
        assert ".style" not in _fn(name), name
