"""The Search pane and the palette's selector lookup, held by reading the
shipped files (ux09-search, 2026-09-22).

Pure: no database, no browser, like test_ui_invariants.py beside it. The
DB-backed half of the same findings is test_search_selectors_pg.py; this
file holds the console to using what that half built, because each finding
was a server that could answer and a console that did not ask, or asked
and did not say.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8").replace("\r\n", "\n")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _css() -> str:
    return (STATIC / "app.css").read_text(encoding="utf-8")


def _function(name: str) -> str:
    """A top-level function's text, up to the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start())]


def _search_region() -> str:
    js = _js()
    start = js.index("/* ── search ──")
    return js[start:js.index("\nfunction focusEvidence(", start)]


def _case_switch_resets(region: str) -> list[str]:
    return re.findall(r"onCaseSwitch\(\(\) => \{(.*?)\n\}\);", region, flags=re.S)


def test_a_case_switch_clears_the_search_pane():
    """stale-results-across-cases: KESTREL showed NIGHTJAR's query and
    hits under its own header and TLP chip, because openCase reset what it
    knew about and the Search pane was not on the list."""
    resets = _case_switch_resets(_search_region())
    assert resets, "the search region registers no case-switch reset"
    body = "\n".join(resets)
    for element in ("search-q", "search-nodes", "search-evidence", "search-scope"):
        assert f"'{element}'" in body, f"a case switch leaves #{element} standing"
    assert "searchSeq" in body, (
        "the reset must also retire any search still in flight, or its "
        "reply lands in the new case's pane")


def test_a_search_reply_from_an_older_case_or_query_is_dropped():
    """The token is taken BEFORE the await and checked AFTER it, and before
    anything is drawn. Checked the other way round the guard is a no-op."""
    run = _function("runSearch")
    token_at = run.index("caseToken()")
    await_at = run.index("await Promise.allSettled")
    guard = re.search(r"if \(caseChanged\(token\) \|\| seq !== searchSeq\) return;", run)
    assert guard, "runSearch does not drop a stale reply"
    assert token_at < await_at < guard.start() < run.index("showSearchColumn(")
    more = _function("moreHits")
    assert "caseChanged(token)" in more and "seq !== searchSeq" in more


def test_the_search_pane_asks_for_and_shows_the_total():
    """silent-truncation-50: 50 of 73 drawn with nothing said."""
    region = _search_region()
    assert "with_total=true" in _function("searchPath")
    hits = _function("renderHits")
    assert "'Showing ' + hits.length + ' of ' + total" in hits
    assert "SEARCH_MAX" in hits, "a capped column offers the rest up to the server cap"
    assert re.search(r"const SEARCH_MAX = 200;", region), (
        "SEARCH_MAX must match `le=200` on the search routes")
    router = (STATIC.parents[0] / "routers" / "search.py").read_text(encoding="utf-8")
    assert router.count("limit: int = Query(50, ge=1, le=200)") >= 3


def test_an_empty_or_failed_column_says_which():
    """A bare "No matches." read as "not in this case"; an empty box after
    a failure read the same way."""
    region = _search_region()
    assert "'No matches.'" not in region
    problem = _function("searchProblem")
    assert "form-error" in problem and "Search failed" in problem


def test_a_selector_hit_shows_the_selector_and_defangs_it():
    """selectors-unsearchable: the hit is the owning entity, with a
    "via selector TYPE value" line. The value is attacker-influenced, so it
    goes through visibleText like the label does (CR14)."""
    via = _function("viaLine")
    assert "'via selector ' + v.selector_type" in via
    assert "visibleText(v.value)" in via
    assert "visibleText(v.merged_from)" in via
    button = _function("hitButton")
    assert "visibleText(hit.label)" in button and "viaLine(hit, q)" in button


def test_the_palette_looks_up_selectors_and_forgets_them_on_a_case_switch():
    js = _js()
    fetch = _function("fetchPaletteSelectors")
    assert "'/search/selectors?with_total=true" in fetch
    assert fetch.index("caseToken()") < fetch.index("await api(")
    assert "caseChanged(token)" in fetch
    start = js.index("const PAL_SEL_DELAY_MS")
    resets = _case_switch_resets(js[start:js.index("function openPalette(", start)])
    assert resets and "resetPalSel()" in resets[0], (
        "the palette's selector cache is case-scoped and must be dropped on "
        "a switch")
    assert "palSel = freshPalSel()" in _function("resetPalSel")
    assert "caseToken()" in _function("freshPalSel")
    assert "palSel !== mine" in fetch, (
        "a reply that lands after a case switch must not fill the new "
        "case's cache")
    add = _function("addSelectorMatches")
    assert "visibleText(hit.label)" in add and "visibleText(v.value)" in add
    assert "schedulePaletteSelectors(" in _function("initPalette")
    assert "addSelectorMatches(" in _function("renderPalette")


def test_a_palette_answer_is_not_kept_past_one_opening_or_its_ttl():
    """Held for the whole case, an empty answer stuck: a wallet looked up
    before it was recorded kept answering "Nothing matches." until a case
    switch or a reload, and reopening the palette sent no request at all
    (verifier of the 2026-09-22 fix)."""
    js = _js()
    assert re.search(r"^const PAL_SEL_TTL_MS = \d+;$", js, flags=re.M)
    assert "resetPalSel()" in _function("openPalette"), (
        "each opening of the palette must ask the server afresh")
    fresh = _function("palSelFresh")
    assert "entry.error" in fresh and "PAL_SEL_TTL_MS" in fresh
    assert "entry.at" in fresh
    schedule = _function("schedulePaletteSelectors")
    assert "palSelFresh(palSel.results.get(sq))" in schedule
    assert "palSel.results.get(sq);\n  if (cached" not in schedule, (
        "a cached answer must be checked for age, not only for presence")
    fetch = _function("fetchPaletteSelectors")
    assert fetch.count("at: Date.now()") == 2, (
        "both the answer and the failure carry the time they were learned")


def test_the_palette_sends_a_value_behind_its_type_label_and_no_command():
    """"ICQ: 123456789" is a spaced query, so the palette never asked the
    server, which reads the label as the type (curation.type_label), and
    answered "Nothing matches." (verifier of the second 2026-09-22 fix
    round). A one-word label and a value go; a two-word command still
    never spends the search meter. The pattern is plain enough to run
    here with Python's `re`, which agrees with JS on ASCII input."""
    js = _js()
    m = re.search(r"^const PAL_SEL_LABELLED = /(.+)/;$", js, flags=re.M)
    assert m, "app.js has no PAL_SEL_LABELLED"
    labelled = re.compile(m.group(1))
    for sent in ("ICQ: 123456789", "ICQ 123456789", "IMEI 490154203237518",
                 "Jabber: ember_hobby", "icq:123456789"):
        assert labelled.search(sent) or not re.search(r"\s", sent), sent
    for kept in ("Save layout", "Fit view", "Clear pins", "Reload graph",
                 "ember hobby", "Go to graph", "Minimum confidence: HIGH", "ICQ: 12"):
        assert not labelled.search(kept), kept
    query = _function("palSelectorQuery")
    assert "PAL_SEL_LABELLED.test(raw)" in query and "!/\\s/.test(raw)" in query
    assert "raw.length < 3" in query


def test_the_markup_and_styles_the_search_code_uses_exist():
    html = _html()
    for element in ("search-help", "search-scope", "palette-remote"):
        assert f'id="{element}"' in html, f"index.html has no #{element}"
    assert 'aria-describedby="search-help"' in html
    css = _css()
    for cls in ("hit-main", "hit-label", "hit-via", "hit-count", "hit-more",
                "search-help", "search-scope", "pal-remote"):
        assert re.search(rf"^\.{cls}\s*\{{", css, flags=re.M), f"app.css has no .{cls}"


def test_the_help_line_promises_only_what_the_server_does():
    """The help says a fragment of three or more characters matches names,
    titles and selectors; that has to stay the server's threshold."""
    help_text = re.search(r'<p id="search-help"[^>]*>(.*?)</p>', _html(), flags=re.S)
    assert help_text and "three" in help_text.group(1)
    curation = (STATIC.parents[1] / "curation.py").read_text(encoding="utf-8")
    assert re.search(r"^FRAGMENT_MIN = 3$", curation, flags=re.M)
    # It also says a value may keep its type label; the server reads it.
    assert "ICQ: 123456789" in help_text.group(1)
    assert re.search(r"^def type_label\(", curation, flags=re.M)


def test_no_em_or_en_dash_in_the_search_copy():
    """House rule for anything a user reads."""
    region = _search_region()
    strings = re.findall(r"'([^'\n]*)'", region)
    html = re.search(r'<section id="pane-search".*?</section>', _html(), flags=re.S)
    for text in strings + [html.group(0)]:
        assert chr(0x2014) not in text and chr(0x2013) not in text, text
