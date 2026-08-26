"""Invariants that live in the analyst console rather than in the API.

The UI is plain HTML and hand-written JavaScript under a strict CSP with no
build step, which was chosen partly so that properties like these are
CHECKABLE by reading the files. A property nobody checks is a property that
survives until the first refactor.

Pure — no database, no browser. These read the shipped static assets.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")

APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"
APP_CSS = STATIC / "app.css"

#: The service package, for the cross-file key contracts below.
SRC = STATIC.parents[1]


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Invariant 10 — samples never render, never execute
# ---------------------------------------------------------------------------

#: An assignment, not a mention. The word appears in three comments
#: explaining why it is not used, and a check that banned the string
#: outright would push those comments out and take the reasoning with them.
_INNER_HTML_WRITE = re.compile(
    r"\.(inner|outer)HTML\s*(=|\+=)|insertAdjacentHTML|"
    r"document\.write|\.srcdoc\s*=")


def test_the_console_never_assigns_html_from_data():
    """Every value the console displays is attacker-influenced somewhere:
    a case label an analyst typed, a forum handle, a filename on a malware
    sample, a fragment of unparseable ingest.

    So the console builds DOM through `document.createElement` and
    `textContent` and never assigns markup. This is the single check that
    keeps that true, because "we use textContent here" is a habit and a
    habit is one hurried fix from ending.
    """
    offenders = [
        (i, line.strip())
        for i, line in enumerate(_js().splitlines(), 1)
        if _INNER_HTML_WRITE.search(line)
    ]
    assert not offenders, (
        "the console assigned markup rather than text:\n"
        + "\n".join(f"  app.js:{i}: {line}" for i, line in offenders))


#: `.src =` was NOT in `_INNER_HTML_WRITE`, and until the phishing pane
#: existed nothing in the console set one. That gap was found by an
#: adversarial pass in 2026-07-26: a single `img.src = row.something`
#: passed every UI test in this file while pointing the browser at an
#: attacker-chosen URL — which fetches it, from the analyst's machine,
#: announcing the investigation (docs/19 §5) and handing over a referer.
#:
#: `.src` cannot simply be banned: the capture pane has to show a
#: screenshot. So it is CONSTRAINED instead — every assignment must be a
#: same-origin API path built from `/api/v1/`, never a value out of a
#: response.
_SRC_WRITE = re.compile(r"\.src\s*=\s*(.+)$")
_SAFE_SRC = re.compile(r"^[`'\"]/api/v1/")


def test_an_image_source_is_always_a_same_origin_api_path():
    """The console may load a screenshot. It may not load a URL that came
    out of a response body.

    A phishing capture's `final_url` is attacker-chosen by construction.
    Assigning it to an `img.src` would make the analyst's browser fetch
    attacker infrastructure — a drive-by surface, a referer leak, and a
    notification to the actor that they are under investigation.
    """
    offenders = []
    for i, line in enumerate(_js().splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        match = _SRC_WRITE.search(stripped)
        if match and not _SAFE_SRC.match(match.group(1).strip()):
            offenders.append((i, stripped))
    assert not offenders, (
        "an image source was built from something other than an /api/v1/ "
        "path:\n" + "\n".join(f"  app.js:{i}: {line}" for i, line in offenders))


def test_no_iframe_and_therefore_no_sandbox_question():
    """Invariant 10: "No sandbox attribute combines `allow-scripts` with
    `allow-same-origin`."

    The console answers that by having no iframe at all. An iframe is the
    only element the rule can apply to, so its absence is a stronger
    guarantee than any review of its attributes -- and a much easier one to
    verify a year from now.
    """
    assert "<iframe" not in _html().lower()
    assert "createElement('iframe'" not in _js()
    assert 'createElement("iframe"' not in _js()


def test_the_lethal_pair_appears_nowhere():
    """The belt to that braces. If an iframe is ever added, this fails
    unless somebody has thought about the attributes -- which is the point
    at which they should be thinking about them."""
    blob = (_html() + _js()).lower()
    if "sandbox" not in blob:
        return
    for match in re.finditer(r"sandbox[^>\n]{0,200}", blob):
        window = match.group(0)
        assert not ("allow-scripts" in window and "allow-same-origin" in window), (
            "allow-scripts with allow-same-origin defeats the sandbox "
            "entirely: the framed document can reach into its parent and "
            "remove the attribute. Invariant 10 forbids the pair.")


def test_the_lab_pane_shows_no_bytes():
    """Metadata may render; bytes may not. The lab pane must not contain a
    preview, a hex dump or an image sourced from a sample."""
    html = _html()
    start = html.index('id="pane-samples"')
    end = html.index("</section>", start)
    pane = html[start:end].lower()
    for forbidden in ("<img", "<canvas", "<object", "<embed", "<video",
                      "<audio", "<iframe"):
        assert forbidden not in pane, (
            f"{forbidden} in the lab pane: sample bytes must never reach a "
            f"renderer, and an element that can fetch or decode is a "
            f"renderer whatever it is pointed at today")


def test_the_download_control_is_not_a_link():
    """A plain <a href> is a GET, and this endpoint is a POST behind step-up
    on purpose: a GET that puts working malware on a disk is one a
    prefetcher, a link scanner or a chat unfurl can fire without a human.

    The anchor `downloadSample` creates is fed an object URL of a blob
    ALREADY fetched with a POST, which is a different thing.
    """
    js = _js()
    start = js.index("async function downloadSample")
    body = js[start:js.index("\nasync function", start + 10)]
    assert "method: 'POST'" in body
    assert "URL.revokeObjectURL" in body, (
        "an object URL left alive is a live sample reachable from the "
        "page's own origin for as long as the tab is open")


# ---------------------------------------------------------------------------
# Deceptive characters — found by looking at a screenshot, not by a test
# ---------------------------------------------------------------------------

def test_bidi_controls_are_substituted_not_merely_isolated():
    """The first version of the filename display used `dir="ltr"` and
    `unicode-bidi: isolate`, which set the BASE direction and leave an
    explicit U+202E doing exactly its job. A seeded filename
    `harmless<RLO>fdp.exe` rendered on screen as `harmlessexe.pdf`.

    The CSS looked like the defence and was not one, and nothing in the
    suite could tell — it took a screenshot and reading it.

    So the characters are SUBSTITUTED before they reach the DOM. This test
    asserts the substitution table covers the bidi overrides, the
    zero-width family and the isolates.
    """
    js = _js()
    assert "function visibleText" in js
    table = js[js.index("const _DECEPTIVE"):js.index("function visibleText")]

    # The class is declared with \u escapes rather than literal invisible
    # characters, so the assertion is on the escapes. That is not a
    # workaround: the literal form was silently mangled in transit while
    # this defence was being written, which is exactly the failure mode a
    # class of unprintable characters has and exactly why a test cannot be
    # written against it.
    ranges: list[tuple[int, int]] = []
    for lo, hi in re.findall(r"\\\\u([0-9A-Fa-f]{4})-\\\\u([0-9A-Fa-f]{4})",
                             table):
        ranges.append((int(lo, 16), int(hi, 16)))
    for single in re.findall(r"\\\\u([0-9A-Fa-f]{4})(?!\s*-)", table):
        point = int(single, 16)
        ranges.append((point, point))
    assert ranges, "no codepoints declared in _DECEPTIVE"

    for codepoint in (
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,   # embeddings and overrides
        0x2066, 0x2067, 0x2068, 0x2069,           # isolates
        0x200E, 0x200F, 0x061C,                   # marks
        0x200B, 0x200C, 0x200D, 0xFEFF,           # zero-width family
    ):
        assert any(lo <= codepoint <= hi for lo, hi in ranges), (
            f"U+{codepoint:04X} is not neutralised; it changes what a "
            f"string looks like without changing what it is")

    # And the reverse: Cyrillic must NOT be caught. The primary venues in
    # this domain are Russian-language, and a rule that fired on almost
    # every handle in the case file would be turned off within a day.
    for codepoint in (0x0410, 0x0430, 0x0413):    # А, а, Г
        assert not any(lo <= codepoint <= hi for lo, hi in ranges), (
            f"U+{codepoint:04X} is Cyrillic and must render as itself")


def test_labels_are_sanitised_at_the_boundary_not_at_each_render_site():
    """An IDENTITY node's label IS a forum handle — the analyst pastes it —
    so it is attacker-chosen, and it is drawn in about two dozen places:
    the canvas, the entity table, the palette, the inspector, the ACH
    matrix, every analytics summary. A per-site fix is a fix that one site
    will always be missing.

    This docstring named "every analytics summary" from the day it was
    written, and the assertions below covered the two graph paths only. The
    analytics suite went to `state` raw and drew eight sets of unsanitised
    names -- `removal_set`, `top_betweenness_set`, `cut_vertices`,
    `bridges`, `triads[].nodes`, `dyads` and the two table paths. A claim in
    a docstring is not a check, and this is the file where that costs the
    most: analytics is the pane that NAMES the people an analyst is about to
    act on.
    """
    js = _js()
    assert "function withSafeLabel" in js
    assert "nodes.map(withSafeLabel)" in js, "the entity list is unsanitised"
    assert "(g.nodes || []).map(withSafeLabel)" in js, \
        "the sociogram projection is unsanitised"
    assert "function safeLabelsDeep" in js, (
        "nested payloads have no boundary sanitiser, so a label more than "
        "one level down is drawn raw")
    assert "state.analytics = safeLabelsDeep(" in js, \
        "the analytics suite is unsanitised"
    assert "state.analyticsKpp = safeLabelsDeep(" in js, \
        "the key-player result is unsanitised"


def test_the_deep_label_sanitiser_covers_the_pair_keys_too():
    """`bridges` and `dyads` carry `source_label`/`target_label` rather than
    `label`, so a sanitiser keyed on `label` alone would de-fang the triads
    and leave the bridges raw -- which is the per-site gap in miniature,
    inside the very helper written to close it."""
    js = _js()
    start = js.index("const _LABEL_KEYS")
    decl = js[start:js.index("\n", start)]
    for key in ("label", "source_label", "target_label"):
        assert f"'{key}'" in decl, f"the deep sanitiser ignores `{key}`"


def test_the_dead_letter_fragment_is_made_visible_too():
    """textContent stops it EXECUTING and does nothing about it LYING, and
    the whole reason to show a fragment is that somebody reads it."""
    assert "visibleText(d.fragment)" in _js()


# ---------------------------------------------------------------------------
# Motion
# ---------------------------------------------------------------------------

def test_no_animation_can_leave_content_invisible():
    """`animation-fill-mode: backwards` holds an element at its `from`
    keyframe for the whole of its delay. With a staggered per-row delay
    that meant a stall in the animation clock left ROWS MISSING with no
    error anywhere — a screenshot of the lab queue showed three samples out
    of twenty-eight beside a count that said 28.

    A hidden tab already clamps timers and suspends the compositor in this
    app. Motion that can hide a row is not worth having in a queue whose
    rows are malware samples.
    """
    # Comments stripped first. The rule this replaced is explained at
    # length in a comment that names `animation-delay`, and a check that
    # matched the comment would push the reasoning out of the file — the
    # same trap the innerHTML check above had to avoid.
    css = re.sub(r"/\*.*?\*/", "", APP_CSS.read_text(encoding="utf-8"),
                 flags=re.S)
    for rule in re.findall(r"\{[^{}]*\}", css):
        if "backwards" not in rule and "both" not in rule:
            continue
        assert "animation-delay" not in rule, (
            "an animation that fills backwards AND is delayed holds its "
            "element invisible for the delay: " + rule.strip())
    # And the delays themselves are gone, so a future edit cannot
    # reintroduce the pair by adding `backwards` back to a rule that still
    # carries a stagger.
    assert "animation-delay" not in css

def test_reduced_motion_is_honoured():
    """Vestibular disorders are not rare, and this is a tool people use for
    a whole shift. Every animation added has to fall under the existing
    blanket rule rather than beside it."""
    css = APP_CSS.read_text(encoding="utf-8")
    assert "@media (prefers-reduced-motion: reduce)" in css
    block = css[css.index("@media (prefers-reduced-motion: reduce)"):][:400]
    assert "animation-duration: 0.001s !important" in block
    assert "transition-duration: 0.001s !important" in block


def test_animations_move_only_composited_properties():
    """`transform` and `opacity` are the two properties a browser can
    animate off the main thread. Animating `width`, `top` or `margin`
    forces a layout pass per frame, and this app renders a sociogram that
    cannot afford one because a card faded in.

    `width` on `.meter-fill` is the deliberate exception: it is a single
    5px bar inside a card, it animates once on open, and a transform-based
    version would scale its own border radius.
    """
    css = APP_CSS.read_text(encoding="utf-8")
    for block in re.findall(r"@keyframes[^{]+\{(.*?)\n\}", css, re.S):
        props = re.findall(r"^\s*([a-z-]+)\s*:", block, re.M)
        for prop in props:
            assert prop in {"opacity", "transform"}, (
                f"keyframe animates {prop!r}, which forces layout or paint "
                f"per frame")


# ---------------------------------------------------------------------------
# The lessons the earlier panes taught, as checks
# ---------------------------------------------------------------------------

def test_every_rail_tab_has_a_pane():
    """A rail button whose pane does not exist shows an empty workspace and
    no error. Cheap to get wrong when adding a tab, invisible in every
    test that does not look."""
    html = _html()
    tabs = set(re.findall(r'data-tab="([a-z-]+)"', html))
    panes = set(re.findall(r'id="pane-([a-z-]+)"', html))
    assert tabs <= panes, f"rail tabs with no pane: {sorted(tabs - panes)}"


def test_every_pane_is_reachable_from_the_rail():
    """And the reverse: a pane nobody can open is dead weight that still
    has to be maintained."""
    html = _html()
    tabs = set(re.findall(r'data-tab="([a-z-]+)"', html))
    panes = set(re.findall(r'id="pane-([a-z-]+)"', html))
    assert panes <= tabs, f"panes with no rail tab: {sorted(panes - tabs)}"


#: Every id app.js looks up by literal name. DERIVED, not listed: the
#: hand-maintained version of this set covered twenty-two ids out of the
#: two hundred and ninety-six that exist, all of them from one pane, so a
#: typo anywhere else was checked by nothing. A curated list of the places
#: somebody remembered to check is not a check.
_ADDRESSED = re.compile(r"\$\('([A-Za-z][\w-]*)'\)")

#: `renderList(listId, emptyId, ...)` resolves both of its first two
#: arguments with `$()` INSIDE the helper, so a typo in either is invisible
#: to the scan above while failing in exactly the same way.
_RENDER_LIST = re.compile(
    r"renderList\(\s*'([A-Za-z][\w-]*)'\s*,\s*'([A-Za-z][\w-]*)'")

#: Ids app.js CREATES for itself (`node.id = 'x'`). These legitimately do
#: not appear in index.html -- `inbox-prefs-msg` is built when the
#: preferences pane renders -- so requiring the markup to declare them
#: would be a false accusation.
_RUNTIME_MADE = re.compile(r"\.id = '([A-Za-z][\w-]*)'")


def _static_ids() -> list[str]:
    js = _js()
    addressed = set(_ADDRESSED.findall(js))
    for list_id, empty_id in _RENDER_LIST.findall(js):
        addressed.add(list_id)
        addressed.add(empty_id)
    return sorted(addressed - set(_RUNTIME_MADE.findall(js)))


@pytest.mark.parametrize("element_id", _static_ids())
def test_element_ids_exist(element_id: str):
    """A typo in either file is a silent no-op at boot -- $() returns null
    and the listener is never attached, so the button simply does nothing
    when clicked, with no error anywhere."""
    assert f'id="{element_id}"' in _html(), (
        f"app.js addresses #{element_id} and index.html does not define it")


def test_the_busy_indicator_cannot_get_stuck_on():
    """A busy bar that never clears is worse than none: it says the app is
    working when it has given up. The decrement has to be in a `finally`,
    because half the calls in this app throw on a 403 by design."""
    js = _js()
    start = js.index("async function api(path, options)")
    body = js[start:js.index("\nasync function", start + 10)]
    assert "_busy(+1)" in body
    assert "finally {" in body and "_busy(-1)" in body, (
        "the indicator is decremented outside a finally, so a throw strands "
        "it on")


def test_the_shortcut_sheet_does_not_hijack_typing():
    """`?` is a printable character. An analyst typing a case note must get
    a question mark, not a modal."""
    js = _js()
    start = js.index("if (e.key === '?'")
    guard = js[start:start + 500]
    assert "isContentEditable" in guard
    assert "'TEXTAREA'" in guard and "'INPUT'" in guard


# ---------------------------------------------------------------------------
# Invariant 12 on screen: a failure must not be reported as a finding
# ---------------------------------------------------------------------------
#
# Added 2026-08-07. Three defects in one family shipped under a green suite,
# all of them in the UI layer, all invisible to an API test: the console
# said something confident about the DATA when the truth was that the code
# had failed or had not been told. Static, for the reason at the top of this
# file -- there is no build step and no browser here, and a check that reads
# the source is the one check that runs.


def test_a_rejection_does_not_claim_a_destruction_it_did_not_perform():
    """`purge_bytes: false` is the LEGAL HOLD path.

    An analyst reaches it because somebody has been ordered to preserve the
    material. Telling them "the bytes are gone" is the worst available wrong
    answer: it invites a spoliation report for a destruction that did not
    happen, and it was the only feedback the screen gave, because the sample
    row does not display whether the object survived.
    """
    js = _js()
    start = js.index("/* --- reject */")
    body = js[start:start + 3000]
    assert "purge_bytes" in body
    # The message has to depend on what was actually sent.
    assert re.search(r"setMsg\(msg,\s*purged\s*\?", body), (
        "the rejection message is unconditional -- it reports the same "
        "outcome whether or not the bytes were destroyed")
    assert "were KEPT" in body, "the preserve case must say so in words"


def test_an_inconclusive_auth_result_is_not_painted_as_a_failure():
    """TEMPERROR/PERMERROR are the receiving MTA saying it could not
    complete the check; NONE means no policy is published.

    `authChip` mapped every non-PASS to the danger colour, which turns a DNS
    timeout at delivery time into an adverse attribution against a sender.
    That is the same conflation `ParsedEmail.gaps` exists to prevent, made
    on screen instead of in the database.
    """
    js = _js()
    start = js.index("function authChip(")
    body = js[start:js.index("\nfunction ", start + 10)]
    assert "TEMPERROR" in body and "PERMERROR" in body, (
        "authChip does not distinguish an inconclusive check from a failed "
        "one")
    assert not re.search(r"===\s*'PASS'\s*\?\s*'good'\s*:\s*'bad'", body), (
        "every non-PASS result is still painted as a failure")


def test_a_partial_collection_run_is_not_painted_as_a_success_or_a_failure():
    """PARTIAL means the poll worked and something inside it could not be
    evaluated -- a watch whose regex will not compile, which matches nothing
    for ever. Painted 'ok' it is invisible, which is how it stayed hidden;
    painted 'bad' it is buried among real fetch failures."""
    js = _js()
    start = js.index("function runRow(")
    body = js[start:js.index("\nfunction ", start + 10)]
    assert "PARTIAL" in body, "runRow cannot show a partially-completed run"


def test_a_failed_path_recompute_does_not_keep_asserting_connectivity():
    """`reapplyFocus` runs on every projection change and every scrubber
    settle. Its path branch swallowed the error and cleared only the
    highlight, leaving `state.focus.connected` and `.hops` holding the
    verdict computed under the PREVIOUS projection -- which the focus flag
    then printed against the new one.

    The false-negative direction is the dangerous one: an earlier NOT
    CONNECTED survives into a projection that would have connected the two,
    and "are these two linked" is the question the control exists to
    answer.

    The ego branch immediately above it already did this correctly, which
    is what makes it a slip rather than a design.
    """
    js = _js()
    start = js.index("async function reapplyFocus(")
    body = js[start:js.index("\n/* \u2500\u2500 timeline scrubber", start)]
    tail = body[body.index("/* path focus */"):]
    assert "state.focus.connected = null" in tail, (
        "a failed path recompute leaves the previous projection's verdict "
        "in place")
    assert "fail(err)" in tail, "and says nothing to the analyst"


def test_the_focus_flag_distinguishes_unknown_from_not_connected():
    """Invariant 12 in the one place it decides an attribution: `false` is
    a finding about the graph, `null` is the absence of one."""
    js = _js()
    start = js.index("function renderFocusFlag(")
    body = js[start:js.index("\n/** Double-click", start)]
    assert "state.focus.connected === null" in body
    assert "UNKNOWN" in body


# ---------------------------------------------------------------------------
# Cross-file key contracts: a green suite either side of a contract that
# neither side asserts
# ---------------------------------------------------------------------------

def _copart_loader() -> str:
    """The co-participation loader.

    Anchored on `loadCoParticipation`, which exists in every version of this
    file, rather than on the renderer added when the defect was fixed. A
    test anchored on the fix fails with "substring not found" against the
    broken code -- which is a test that cannot state what is wrong, only
    that something is.
    """
    js = _js()
    start = js.index("async function loadCoParticipation(")
    return js[start:js.index("\n/* --- Report", start)]


def test_the_co_participation_pane_reads_the_keys_the_service_emits():
    """This pane rendered the literal string "undefined — undefined" on
    every row, under 1444 passing tests, for as long as it has existed.

    It read `t.source`/`t.a` for the endpoints and the service emits
    `src`/`dst`; it read `t.rooms` and the service emits
    `shared_conversations`. Both sides were internally consistent and both
    were tested -- `test_coparticipation_pg.py` asserts the SERVER key and
    the UI tests asserted element ids. Nothing asserted the contract
    BETWEEN them, so the defect sat in the gap where neither suite looked.

    Text-level by necessity (there is no browser here), which is enough:
    it fails the moment either side renames a key without the other.
    """
    service = (SRC / "coparticipation.py").read_text(encoding="utf-8")
    for key in ("src", "dst", "weight", "shared_conversations",
                "inference_method", "nodes", "coverage", "reading"):
        assert f'"{key}"' in service, (
            f"the pane reads `{key}` and coparticipation.py no longer "
            f"emits it -- the pane will render undefined, not fail")


def test_the_co_participation_pane_does_not_read_keys_that_never_existed():
    """The specific dead keys, named so a refactor cannot quietly restore
    them. `body.ties` never existed either -- it was a fallback in front of
    the real key, which is what made the bug survive review."""
    pane = _copart_loader()
    for dead in ("t.source", "t.target", "t.a", "t.b", "t.rooms",
                 "t.weighting", "body.warnings", "body.ties"):
        # Word-bounded, not substring: `t.a` occurs inside
        # `host.appendChild`, and a check that fails on its own test file is
        # a check nobody keeps.
        assert not re.search(rf"\b{re.escape(dead)}\b", pane), (
            f"the co-participation pane reads `{dead}`, which the service "
            f"has never emitted")


def test_the_co_participation_cap_reports_itself():
    """`coparticipation.py`: "a cap that silently drops data is worse than
    no cap, because the output looks complete." The browser dropped the
    entire coverage block, so the one cap the module refuses to apply
    silently was, on screen, silent.

    Scans the whole file, not the loader: the coverage block is rendered by
    a helper the loader calls, and where it lives is not the contract."""
    js = _js()
    assert "cov.oversized" in js or "coverage.oversized" in js, (
        "the oversized-room exclusions are not rendered anywhere")
    assert "participants_excluded_not_visible" in js, (
        "a network made smaller by the caller's clearance does not say so")


def test_the_co_participation_labels_go_through_the_bidi_guard():
    """A HANDLE vertex's label is a string the subject chose on a forum. A
    right-to-left override in it reorders the two names either side of the
    dash, so the tie reads backwards while the DOM says otherwise."""
    pane = _copart_loader()
    assert "visibleText(" in pane, (
        "co-participation renders attacker-chosen handles raw")


def test_a_failed_deception_load_clears_the_previous_case_rows():
    """All three deception panes reported the error into the COUNTS span and
    returned before the render, so the list kept whatever it last held.

    Open Deception on case A, switch to case B, get a 403 -- and case A's
    defanged attacker URLs, BEC subject lines and spoofed caller IDs sit
    under case B's header and its TLP chip. The 403 is the likely path, not
    the rare one: all three endpoints gate on `evidence.read`.
    """
    js = _js()
    assert "function deceptionLoadFailed(" in js, (
        "the three deception loaders no longer share a failure path, so "
        "one of them is the one somebody forgot")
    start = js.index("function deceptionLoadFailed(")
    body = js[start:js.index("\nasync function", start)]
    assert "renderList(" in body, "the stale rows are not cleared"
    assert "refusalText(" in body, "a refusal is not named"
    assert ".counts).textContent = ''" in body, (
        "a stale count survives a failed load")

    # And every loader actually routes its catch through it.
    for loader in ("loadCaptures", "loadDeceptionEmails", "loadDeceptionCalls"):
        s = js.index(f"async function {loader}(")
        fn = js[s:js.index("\n}", s)]
        assert "deceptionLoadFailed(" in fn, (
            f"{loader} still reports a failure without clearing the list")


def test_the_ingest_quarantine_latches_only_on_a_permission_refusal():
    """The latch exists for a good reason -- `ingest.manage` is SYS_ADMIN
    only, and re-probing hums AUTHZ_DENIED into the one signal a security
    officer reads for probing -- but it was keyed on "anything that is not a
    step-up expiry".

    That swept in a network drop (ApiError status 0), a 502, a 503 and a
    429. One blip hid the section for the rest of the session with no
    message at all, which reports a transport failure as a permission fact
    and reports it by making the evidence disappear.
    """
    js = _js()
    start = js.index("async function loadQuarantine(")
    body = js[start:js.index("\n/* --- dead letters", start)]
    assert "err.status === 403" in body, (
        "the quarantine latch is not keyed on the 403 it was written for")
    assert "if (!stepUp) state.quarantineVisible = false;" not in body, (
        "the old catch-all predicate is back: every transient failure "
        "latches the pane off for the session")
    # A transient failure must say the queue is UNKNOWN, not empty.
    assert "not known to be" in body, (
        "a failed read leaves the section reading as 'nothing unattached', "
        "which is a claim about the data")


# ---------------------------------------------------------------------------
# Metric history — Phase 3's "visible" trend
# ---------------------------------------------------------------------------

def _history_js() -> str:
    js = _js()
    start = js.index("async function loadMetricHistory(")
    return js[start:js.index("\nfunction renderKeyPlayer(", start)]


def test_the_trend_calls_the_endpoint_that_exists():
    """ROADMAP-REMAINING.md named this route `metrics/history` until
    2026-08-10. The real path is `analytics/history/{node_id}`, so anyone
    grepping the string the roadmap gave them found nothing and concluded
    the endpoint had never been built."""
    js = _js()
    assert "'/analytics/history/'" in js, (
        "nothing calls the metric-history endpoint")
    assert "metrics/history" not in js, (
        "the roadmap's wrong path has been copied into the client")


def test_the_trend_never_shares_a_promise_all_with_the_suite():
    """A `Promise.all` over endpoints with different permissions is wrong:
    the first 403 rejects the lot, so a caller holding four permissions of
    five sees an empty pane claiming they hold none. Here it would be worse
    -- the suite has already rendered, and a trend failure would blank it.
    """
    body = _history_js()
    assert "Promise.all" not in body, (
        "the trend was folded into a Promise.all, so its failure can blank "
        "a table that loaded successfully")


def test_a_refused_trend_is_not_reported_as_an_empty_one():
    """"No history" and "you may not see the history" are different facts
    and an analyst acts on them differently. The 200-with-no-rows case has
    its own wording, and neither borrows the other's."""
    body = _history_js()
    assert "err.status === 403" in body, "the refusal is not distinguished"
    assert "refusalText(" in body, "the refusal is not named"
    js = _js()
    start = js.index("function renderMetricHistory(")
    render = js[start:js.index("\nfunction histRow(", start)]
    assert "at least two runs" in render, (
        "an authorised-but-empty series does not say what it means")


def test_the_trend_is_drawn_oldest_first():
    """`analytics_runs` orders `started_at DESC` -- newest first. A
    left-to-right time axis has to reverse it, and getting that backwards
    silently INVERTS every trend on screen: rising reads as falling, on the
    one chart whose whole purpose is to show a direction."""
    body = _history_js()
    assert ".slice().reverse()" in body, (
        "the series is charted in API order, so the time axis runs "
        "backwards and every trend is inverted")


def test_an_unrenderable_value_is_not_drawn_as_a_position():
    """A guard, and deliberately not called gap handling.

    `analytics_runs` writes no row when a metric is undefined for a node
    (`if value is None: continue`), and `node_metric.value` is NOT NULL --
    so an undefined run is ABSENT from the series rather than null, and
    absent cannot be told from "no run happened" at this endpoint. The line
    spans it. The pane says so in its help text instead of implying the
    axis is continuous, which is the assertion below.

    The `pen` break still matters: if a value ever arrives unrenderable, it
    must not be drawn as a position.
    """
    body = _history_js()
    assert "pen = false" in body, (
        "an unrenderable value would be drawn at some position anyway")
    html = _html()
    start = html.index("Trend &mdash; one actor across past runs")
    # Whitespace-normalised: the source wraps prose at 72 columns, so any
    # phrase long enough to be worth asserting on is split by a newline and
    # an indent. A test that cannot survive re-wrapping is a test that gets
    # deleted the first time somebody reflows the file.
    help_text = re.sub(r"\s+", " ", html[start:html.index("</p>", start)])
    assert "does not appear here at all" in help_text, (
        "the pane does not disclose that a run with no defined value for "
        "this actor is invisible to it, so a straight segment reads as "
        "'nothing changed' when it may be 'not measured'")


def test_the_trend_canvas_has_an_accessible_twin():
    """The canvas is `aria-hidden`, like the density strip. That is only
    honest if everything it shows also exists as text -- otherwise the
    trend is information that exists solely in pixels."""
    html = _html()
    assert 'id="an-hist-chart"' in html and 'aria-hidden="true"' in html
    assert 'id="an-hist-body"' in html, "no table twin for the chart"
    js = _js()
    assert "function histRow(" in js, "the table twin has no row renderer"


def test_the_approvals_pane_uses_the_servers_operation_key():
    """The first version of the dual-control pane sent the operation as
    `'MERGE'`. `approvals.py` keys its catalogue by `'node.merge'` and
    answers anything else with "unknown operation", so raising a request
    400'd -- and the Execute-merge button, which compared `a.operation`
    against the SAME wrong string, could never appear.

    Both halves of the pane were internally consistent and wrong
    together. That is precisely the defect the co-participation pane
    shipped, reappearing in the pane written after it, which is why the
    key is now a named constant with this test behind it.
    """
    js = _js()
    service = (SRC / "approvals.py").read_text(encoding="utf-8")

    match = re.search(r"const MERGE_OPERATION = '([^']+)'", js)
    assert match, "the merge operation key is inlined again rather than named"
    key = match.group(1)
    assert f'"{key}": Operation(' in service, (
        f"app.js raises approvals for operation {key!r} and approvals.py's "
        f"OPERATIONS catalogue has no such key -- the request 400s")

    start = js.index("async function loadApprovals(")
    pane = js[start:js.index("\nasync function reverseMerge(", start)]
    assert "'MERGE'" not in pane, (
        "a display-style operation string is back in the approvals pane")


def test_the_admin_pane_offers_exactly_the_roles_the_server_grants():
    """Three lists had to agree and two drifted: `GRANTABLE_ROLES` in
    `iam_admin.py` (which the server enforces), the create form's picker
    in index.html, and the per-row grant dropdown in app.js.

    The server's list was widened to ten roles and both pickers still
    offered six, so COLLECTOR was grantable by `curl` and unreachable
    from the panel whose entire purpose is that nobody needs `curl`. A
    role offered but refused, or refused but offered, is the same
    cross-file contract defect the co-participation pane shipped.
    """
    import ast

    src = (SRC / "iam_admin.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    server = None
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and any(getattr(t, "id", None) == "GRANTABLE_ROLES"
                        for t in node.targets)):
            # frozenset({...})
            server = {
                el.value for el in node.value.args[0].elts
                if isinstance(el, ast.Constant)
            }
    assert server, "GRANTABLE_ROLES not found in iam_admin.py"

    js = _js()
    match = re.search(r"const GRANTABLE_ROLES = \[(.*?)\];", js, re.S)
    assert match, "app.js no longer names the grantable roles once"
    ui = set(re.findall(r"'([A-Z_]+)'", match.group(1)))
    assert ui == server, (
        f"app.js and iam_admin.py disagree: only in JS {ui - server}, "
        f"only in Python {server - ui}")

    html = _html()
    start = html.index('id="adm-roles"')
    picker = html[start:html.index("</select>", start)]
    form = set(re.findall(r"<option[^>]*>([A-Z_]+)</option>", picker))
    assert form == server, (
        f"the create form's picker disagrees with the server: only in HTML "
        f"{form - server}, only in Python {server - form}")

    # SERVICE is a machine identity and must not be offered anywhere.
    assert "SERVICE" not in server and "SERVICE" not in ui
