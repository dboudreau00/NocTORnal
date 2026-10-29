"""Invariants that live in the analyst console rather than in the API.

The UI is plain HTML and hand-written JavaScript under a strict CSP with no build step, which was
chosen partly so that properties like these are CHECKABLE by reading the files.

Pure: no database, no browser. These read the shipped static assets.
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
    """Every value the console displays is attacker-influenced somewhere (a case label, a forum handle,
    a filename on a malware sample, a fragment of unparseable ingest), so the console builds DOM through
    `document.createElement` and `textContent` and never assigns markup. This is the single check that
    keeps that true."""
    offenders = [
        (i, line.strip())
        for i, line in enumerate(_js().splitlines(), 1)
        if _INNER_HTML_WRITE.search(line)
    ]
    assert not offenders, (
        "the console assigned markup rather than text:\n"
        + "\n".join(f"  app.js:{i}: {line}" for i, line in offenders))


#: `.src =` is not in `_INNER_HTML_WRITE`, so a single `img.src = row.something` would pass the other
#: UI tests while pointing the browser at an attacker-chosen URL, which fetches it from the analyst's
#: machine, announcing the investigation (docs/19, section 5) and handing over a referer.
#:
#: `.src` cannot simply be banned: the capture pane has to show a screenshot. So it is CONSTRAINED:
#: every assignment must be a same-origin API path built from `/api/v1/`, never a value out of a
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
    """Invariant 10: "No sandbox attribute combines `allow-scripts` with `allow-same-origin`."

    The console answers that by having no iframe at all. An iframe is the only element the rule can
    apply to, so its absence is a stronger guarantee than any review of its attributes, and easier to
    verify.
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
    """Bidi controls are SUBSTITUTED before they reach the DOM, not merely isolated.

    `dir="ltr"` and `unicode-bidi: isolate` set the BASE direction and leave an explicit U+202E doing
    its job: a filename `harmless<RLO>fdp.exe` renders as `harmlessexe.pdf`. This test asserts the
    substitution table covers the bidi overrides, the zero-width family and the isolates.
    """
    js = _js()
    assert "function visibleText" in js
    table = js[js.index("const _DECEPTIVE"):js.index("function visibleText")]

    # The class is declared with unicode escapes rather than literal invisible characters, so the
    # assertion is on the escapes: literal unprintable characters are easily mangled in transit.
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
    """An IDENTITY node's label IS a forum handle (the analyst pastes it), so it is attacker-chosen,
    and it is drawn in about two dozen places: the canvas, the entity table, the palette, the
    inspector, the ACH matrix, every analytics summary. A per-site fix is a fix that one site will
    always be missing, so labels are sanitised at the boundary.

    The assertions cover the two graph paths and the analytics paths (`removal_set`,
    `top_betweenness_set`, `cut_vertices`, `bridges`, `triads[].nodes`, `dyads` and the two table
    paths): analytics is the pane that NAMES the people an analyst is about to act on.
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
    """`animation-fill-mode: backwards` holds an element at its `from` keyframe for the whole of its
    delay. With a staggered per-row delay, a stall in the animation clock leaves ROWS MISSING with no
    error anywhere (a lab queue showing three samples of twenty-eight beside a count that said 28). A
    hidden tab already clamps timers and suspends the compositor in this app, and motion that can hide
    a row is not worth having in a queue of malware samples.
    """
    # Comments stripped first: a comment naming `animation-delay` would otherwise match the check and
    # push the reasoning out of the file.
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
    """`transform` and `opacity` are the two properties a browser can animate off the main thread.
    Animating `width`, `top` or `margin` forces a layout pass per frame, which the sociogram cannot
    afford.

    `width` on `.meter-fill` is the deliberate exception: it is a single
    5px bar inside a card, it animates once on open, and a transform-based
    version would scale its own border radius.
    """
    css = APP_CSS.read_text(encoding="utf-8")
    # Scan INSIDE each step's braces: every keyframe line begins with a selector (`from {`,
    # `0%, 100% {`) with the properties after the brace on the same line, so a scan anchored on line
    # start extracts nothing and passes on any animation. The sentinel at the end matters: a check that
    # matches nothing must fail, not pass.
    seen = 0
    for name, body in re.findall(r"@keyframes\s+([\w-]+)\s*\{(.*?)\n\}", css, re.S):
        for step in re.findall(r"\{([^{}]*)\}", body):
            for prop in re.findall(r"([a-z-]+)\s*:", step):
                seen += 1
                assert prop in {"opacity", "transform"}, (
                    f"@keyframes {name} animates {prop!r}, which forces "
                    f"layout or paint per frame")
    assert seen > 0, ("the keyframe scan extracted nothing; a check that "
                      "matches nothing passes on any CSS")


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


#: Every id app.js looks up by literal name. DERIVED, not listed: a curated list covers only the
#: places somebody remembered to check, so a typo anywhere else would be checked by nothing.
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


# Invariant 12 on screen: a failure must not be reported as a finding. The console must not say
# something confident about the DATA when the code has failed or has not been told. Static, for the
# reason at the top of this file.


def test_a_rejection_does_not_claim_a_destruction_it_did_not_perform():
    """`purge_bytes: false` is the LEGAL HOLD path.

    An analyst reaches it because somebody has been ordered to preserve the material. Telling them "the
    bytes are gone" is the worst available wrong answer: it invites a spoliation report for a
    destruction that did not happen, and it is the only feedback the screen gives, because the sample
    row does not display whether the object survived.
    """
    js = _js()
    body = _js_function("sampleActions")
    assert "purge_bytes: purged" in body
    # The outcome is reported from the SERVER's answer, `bytes_disposition`: rejection preserves by
    # default, there are three outcomes, and only the server knows which one it applied.
    assert "DISPOSITION_TEXT[out.bytes_disposition]" in body, (
        "the rejection message does not come from what the server did")
    words = js[js.index("const DISPOSITION_TEXT"):]
    words = words[:words.index("};")]
    for disposition in ("preserved:", "destroyed:", "kept:"):
        assert disposition in words, disposition
    assert "left where they were" in words, (
        "the record-only case must say in words that nothing was disposed of")


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
    """`reapplyFocus` runs on every projection change and every scrubber settle. Its path branch must
    clear `state.focus.connected` and `.hops` on failure, not only the highlight, or the verdict
    computed under the PREVIOUS projection is printed against the new one.

    The false-negative direction is the dangerous one: an earlier NOT CONNECTED survives into a
    projection that would have connected the two, and "are these two linked" is the question the
    control exists to answer. The ego branch above it does this correctly.
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
    """The pane reads the keys the service emits: `src`/`dst` for the endpoints and
    `shared_conversations`, not `t.source`/`t.a` and `t.rooms`, which rendered the literal string
    "undefined" for both endpoints on every row.

    `test_coparticipation_pg.py` asserts the SERVER key and the UI tests assert element ids; nothing
    else asserts the contract BETWEEN them. Text-level by necessity (there is no browser here), which
    is enough: it fails the moment either side renames a key without the other.
    """
    service = (SRC / "coparticipation.py").read_text(encoding="utf-8")
    for key in ("src", "dst", "weight", "shared_conversations",
                "inference_method", "nodes", "coverage", "reading"):
        assert f'"{key}"' in service, (
            f"the pane reads `{key}` and coparticipation.py no longer "
            f"emits it -- the pane will render undefined, not fail")


def test_the_co_participation_pane_does_not_read_keys_that_never_existed():
    """The dead keys are named so a refactor cannot quietly restore them. `body.ties` never existed
    either: it was a fallback in front of the real key."""
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
    """The latch exists for a good reason: `ingest.manage` is SYS_ADMIN only, and re-probing hums
    AUTHZ_DENIED into the one signal a security officer reads for probing. So it latches only on a
    permission refusal (403), not on "anything that is not a step-up expiry".

    A network drop (ApiError status 0), a 502, a 503 or a 429 must not hide the section for the rest of
    the session with no message, which reports a transport failure as a permission fact by making the
    evidence disappear.
    """
    js = _js()
    start = js.index("async function loadQuarantine(")
    body = js[start:js.index("\n/* --- dead letters", start)]
    assert "err.status === 403" in body, (
        "the quarantine latch is not keyed on the 403 it was written for")
    assert "if (!stepUp) state.quarantineVisible = false;" not in body, (
        "the old catch-all predicate is back: every transient failure "
        "latches the pane off for the session")
    # A transient failure must say the queue is UNKNOWN, not empty. It goes through the shared notice:
    # written into the empty line, it would outlive the failure.
    assert "showLoadFailure('ing-quarantine-empty'" in body, (
        "a failed read leaves the section reading as 'nothing unattached', "
        "which is a claim about the data")


# Metric history

def _history_js() -> str:
    js = _js()
    start = js.index("async function loadMetricHistory(")
    return js[start:js.index("\nfunction renderKeyPlayer(", start)]


def test_the_trend_calls_the_endpoint_that_exists():
    """The trend calls `analytics/history/{node_id}`, the real path, not `metrics/history`, so a grep
    for the route finds it."""
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
    # refusedWords names a 403/404 through refusalText and gives a 400 the server's own reason (see
    # test_ui_failure_states.py).
    assert "refusedWords(" in body, "the refusal is not named"
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

    `analytics_runs` writes no row when a metric is undefined for a node (`if value is None: continue`),
    and `node_metric.value` is NOT NULL, so an undefined run is ABSENT from the series rather than
    null, and absent cannot be told from "no run happened" at this endpoint. The line spans it. The
    pane says so in its help text instead of implying the axis is continuous, which is the assertion
    below.

    The `pen` break still matters: if a value ever arrives unrenderable, it
    must not be drawn as a position.
    """
    body = _history_js()
    assert "pen = false" in body, (
        "an unrenderable value would be drawn at some position anyway")
    html = _html()
    start = html.index("Trend: one entity across past runs")
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
    """The dual-control pane sends the operation as the server's catalogue key.

    `approvals.py` keys its catalogue by `'node.merge'` and answers anything else with "unknown
    operation", so a request raised with `'MERGE'` would 400, and the Execute-merge button, comparing
    `a.operation` against the same wrong string, could never appear. The key is a named constant with
    this test behind it: two halves internally consistent and wrong together.
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
    """Three lists must agree: `GRANTABLE_ROLES` in `iam_admin.py` (which the server enforces), the
    create form's picker in index.html, and the per-row grant dropdown in app.js.

    A role offered but refused, or refused but offered, is a cross-file contract defect: a role the
    server grants but the panel does not offer is reachable only by `curl`, which the panel exists to
    avoid.
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

    # The create form's roles are checkboxes: a native multi-select drops the pre-chosen ANALYST on a
    # plain click. Their VALUES are the keys.
    html = _html()
    start = html.index('id="adm-roles"')
    picker = html[start:html.index("</fieldset>", start)]
    form = set(re.findall(r'<input type="checkbox" value="([A-Z_]+)"', picker))
    assert form == server, (
        f"the create form's picker disagrees with the server: only in HTML "
        f"{form - server}, only in Python {server - form}")

    # SERVICE is a machine identity and must not be offered anywhere.
    assert "SERVICE" not in server and "SERVICE" not in ui


# ---------------------------------------------------------------------------
# Invariant -- the watch-hit "matched on" contract holds across three files
# ---------------------------------------------------------------------------

def test_the_watch_hit_reason_is_a_list_on_every_side_of_the_contract():
    """The collector writes `matched_on` as a JSON LIST of reasons ("regex:...", "selector:..."), so
    the console must not render `Object.keys()` of it, which on a list gives its indices ("0",
    "0, 1").

    The shape is asserted on all three sides at once (collector, fixture, console), from the one file
    that reads all of them, because two internally consistent halves can be wrong together.
    """
    src = STATIC.parents[1]
    collector = (src / "collection.py").read_text(encoding="utf-8")
    fixture = (Path(__file__).with_name("test_collection_readpath_pg.py")
               .read_text(encoding="utf-8"))
    js = _js()

    # 1. The writer builds a list.
    assert re.search(r"matched\.append\(", collector), (
        "collection.py no longer builds matched_on with list.append -- "
        "re-check the shape before trusting the two assertions below")

    # 2. The fixture writes the same shape (a JSON array, not an object).
    m = re.search(r"matched_on,[^;]*?VALUES\s*\([^)]*?'(\[[^']*\])'::jsonb",
                  fixture, flags=re.S)
    assert m, ("test_collection_readpath_pg._hit must insert matched_on as a "
               "JSON ARRAY, matching what the collector writes")
    assert not re.search(r"matched_on\"\]\s*==\s*\{", fixture), (
        "the read-path test asserts matched_on is a dict; the collector "
        "writes a list")

    # 3. The renderer handles the list as a list.
    row = re.search(r"function watchHitRow\b.*?\n\}", js, flags=re.S)
    assert row, "watchHitRow() is gone -- update this test with the renderer"
    assert "Array.isArray(h.matched_on)" in row.group(0), (
        "watchHitRow renders matched_on without checking for a list; "
        "Object.keys() of a list is its indices")


# ---------------------------------------------------------------------------
# Invariant -- the drain's counters all survive the HTTP boundary
# ---------------------------------------------------------------------------

def test_the_drain_response_declares_every_counter_the_drain_returns():
    """`transports.dispatch_due` returns five counters; `DrainOut` must declare all of them. Pydantic
    drops an undeclared key silently, so `revoked` (the count of people deliberately NOT told because
    their clearance or assignment was revoked after the row was queued) would be computed on every
    drain and reach nobody.

    Asserted structurally so the next counter cannot vanish the same way: every key the service builds
    must be a declared field.
    """
    src = STATIC.parents[1]
    transports = (src / "transports.py").read_text(encoding="utf-8")
    m = re.search(r"counters\s*=\s*\{(.*?)\}\s*\n", transports, flags=re.S)
    assert m, "transports.dispatch_due no longer builds a `counters = {...}` dict"
    returned = set(re.findall(r'"([a-z_]+)"\s*:', m.group(1)))
    assert returned >= {"sent", "refused", "failed", "revoked"}, returned

    from noctornal_api.http.routers.notifications import DrainOut
    declared = set(DrainOut.model_fields)
    missing = returned - declared
    assert not missing, (
        f"dispatch_due returns {sorted(missing)} and DrainOut does not declare "
        "them; pydantic will drop them from the response without an error")


# The static files stay inside the CSP that serves them. `_UI_CSP` (http/app.py) is script-src 'self',
# style-src 'self', connect-src 'self', img-src 'self' data:, with no 'unsafe-inline' and no font-src.
# A webfont @import or a CDN <script> would pass every test and break only in a browser, silently,
# because a blocked resource is a console line, not an error anybody tests for.

def _css_body(name: str) -> str:
    return re.sub(r"/\*.*?\*/", "", (STATIC / name).read_text(encoding="utf-8"),
                  flags=re.S)


def _js_body(name: str) -> str:
    js = re.sub(r"/\*.*?\*/", "", (STATIC / name).read_text(encoding="utf-8"),
                flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", js)


#: A URL that leaves the origin: any scheme (https:, data:, blob:,
#: javascript:) or a protocol-relative //host.
_LEAVES_ORIGIN = re.compile(r"^\s*(?:[a-z][a-z0-9+.\-]*:|//)", re.I)
#: Every attribute through which markup can name a URL.
_URL_ATTR = re.compile(
    r"""\b(?:src|href|action|formaction|poster|data|srcset|ping)\s*=\s*["']([^"']*)["']""",
    re.I)


def test_index_html_references_only_same_origin_relative_paths():
    bad = [v for v in _URL_ATTR.findall(_html()) if _LEAVES_ORIGIN.match(v)]
    assert not bad, f"index.html references off-origin or scheme URLs: {bad}"


def test_index_html_has_no_inline_script_style_or_handlers():
    """No 'unsafe-inline' anywhere in the policy. An inline block or
    handler is not merely untidy: the browser refuses it, and whatever it
    was wired to simply does nothing."""
    html = _html()
    assert not re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html, re.I), "inline <script>"
    assert not re.findall(r"<style\b", html, re.I), "inline <style>"
    assert not re.findall(r"\sstyle\s*=", html, re.I), "style= attribute"
    assert not re.findall(r"\son[a-z]+\s*=", html, re.I), "on*= handler"
    assert not re.findall(r"<base\b", html, re.I), "base-uri 'none' forbids <base>"
    assert not re.findall(r"<meta[^>]*http-equiv", html, re.I), "a meta CSP would shadow the header"
    assert not re.findall(
        r"<link[^>]*rel=[\"'](?:preconnect|dns-prefetch|prefetch|preload)", html, re.I)


@pytest.mark.parametrize("name", ["app.css", "theme.css"])
def test_stylesheets_import_nothing_and_fetch_nothing_off_origin(name: str):
    css = _css_body(name)
    assert "@import" not in css, f"{name} has an @import; style-src 'self' blocks it"
    off = [m.group(0) for m in re.finditer(
        r"url\(\s*['\"]?\s*(?:[a-z][a-z0-9+.\-]*:|//)[^)]*\)", css, re.I)]
    assert not off, f"{name} fetches off-origin or scheme URLs: {off}"
    assert "@font-face" not in css, (
        f"{name} declares a webfont; the CSP has no font-src and the stack "
        f"was chosen to ship no font files")


_FETCH = re.compile(r"\bfetch\(\s*([^,)]+)")
_WS = re.compile(r"new WebSocket\(\s*([^)]+)\)")
_WORKER = re.compile(r"new Worker\(\s*([^)]+)\)")


@pytest.mark.parametrize("name", ["app.js", "layout-worker.js"])
def test_scripts_talk_only_to_their_own_origin(name: str):
    """Same-origin API calls are fetch(API + ...); the WebSocket is built
    from location.host; the worker is a relative script name. Anything
    else is a connection the CSP will refuse at runtime."""
    js = _js_body(name)
    for arg in _FETCH.findall(js):
        assert arg.strip().startswith("API +"), f"{name}: fetch() not rooted at API: {arg!r}"
    for arg in _WS.findall(js):
        assert "${location.host}${API}" in arg, f"{name}: WebSocket not same-origin: {arg!r}"
    for arg in _WORKER.findall(js):
        assert re.fullmatch(r"['\"][\w./-]+\.js['\"]", arg.strip()), f"{name}: Worker from {arg!r}"
    assert not re.search(r"https?://", js), f"{name} carries an absolute http(s) URL"
    assert not re.search(r"['\"`]//", js), f"{name} carries a protocol-relative URL"
    assert not re.search(
        r"new EventSource\(|XMLHttpRequest|sendBeacon\(|importScripts\(|\bimport\(", js)
    assert not re.search(
        r"createElement\(\s*['\"](?:script|link|iframe|object|embed)['\"]", js), (
        f"{name} inserts a resource-loading element at runtime")
    assert not re.search(r"\beval\(|new Function\(", js), "script-src 'self' has no 'unsafe-eval'"
    assert not re.search(r"\.style\s*=|\.cssText\s*=|setAttribute\(\s*['\"]style['\"]", js), (
        "style-src 'self' with no 'unsafe-inline' blocks style attribute writes")
    # `.href =` is allowed ONLY for an object URL of a blob already fetched.
    for m in re.finditer(r"\.href\s*=\s*([^;]+);", js):
        assert m.group(1).strip() == "url", f"{name}: .href assigned from {m.group(1).strip()!r}"


def test_the_console_is_served_under_the_ui_csp(monkeypatch):
    """The header, not only the files. Nothing requested /ui in the suite,
    so the policy the files are held to above was itself unasserted. A
    database is not needed: the console is StaticFiles."""
    from fastapi.testclient import TestClient
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@192.0.2.1:5432/x")
    from noctornal_api.http.app import _UI_CSP, create_app
    client = TestClient(create_app())
    for path in ("/ui/", "/ui/app.js", "/ui/app.css"):
        r = client.get(path)
        assert r.status_code == 200, (path, r.status_code)
        assert r.headers["Content-Security-Policy"] == _UI_CSP, path
        assert "unsafe-inline" not in _UI_CSP
        assert "unsafe-eval" not in _UI_CSP
    # And the API keeps the stricter default-src 'none' -- the UI policy
    # must not leak onto it.
    r = client.get("/healthz")
    assert r.headers["Content-Security-Policy"].startswith("default-src 'none'")


# Contracts the console and the API each hold half of; these tests read both halves


def _ach_block() -> str:
    """The ACH pane, anchored on `renderAchMatrix`, which exists in every
    version of the file, and closed on the PGP block that follows it."""
    js = _js()
    start = js.index("function renderAchMatrix(")
    return js[start:js.index("\n/* --- PGP verification", start)]


def test_the_ach_cells_call_the_stance_route_with_the_routers_vocabulary():
    """`PUT /cases/{id}/ach/hypotheses/{hid}/stance` is the only way to score evidence against a
    hypothesis, so `renderAchMatrix` must wire its cells to it, not draw them as a `<td>` with a
    tooltip.

    Reads both sides: the route the console calls must be the one the router defines, the payload keys
    must be `StanceBody`'s, and the stances the chooser offers must be exactly the integers the
    router's `Field(ge=, le=)` accepts and the service labels.
    """
    import ast

    router_src = (SRC / "http" / "routers" / "ach.py").read_text(encoding="utf-8")
    assert re.search(r'@router\.put\("/hypotheses/\{hypothesis_id\}/stance"',
                     router_src), "the router no longer defines the stance route"
    assert 'prefix="/cases/{case_id}/ach"' in router_src

    block = _ach_block()
    assert "'/ach/hypotheses/'" in block and "'/stance'" in block, (
        "the console never calls the stance route: the matrix cannot be "
        "scored from the UI")
    assert "method: 'PUT'" in block, "the stance is not sent as a PUT"

    # The payload the console builds is the model the router parses.
    from noctornal_api.http.routers.ach import StanceBody
    for key in StanceBody.model_fields:
        assert re.search(rf"\b{key}:", block), (
            f"the console's stance payload has no `{key}`, which StanceBody "
            f"requires or would silently default")

    # The vocabulary: Field(ge=-2, le=2) on the router, STANCE_LABEL on the
    # service, ACH_STANCES on the console. Three copies, one test.
    tree = ast.parse(router_src)
    bounds: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "StanceBody":
            for stmt in node.body:
                if (isinstance(stmt, ast.AnnAssign)
                        and getattr(stmt.target, "id", None) == "stance"
                        and isinstance(stmt.value, ast.Call)):
                    for kw in stmt.value.keywords:
                        if kw.arg in {"ge", "le"}:
                            bounds[kw.arg] = ast.literal_eval(kw.value)
    assert set(bounds) == {"ge", "le"}, "StanceBody.stance lost its bounds"
    router_accepts = set(range(bounds["ge"], bounds["le"] + 1))

    from noctornal_api.ach import STANCE_LABEL
    assert set(STANCE_LABEL) == router_accepts

    m = re.search(r"const ACH_STANCES = \[([^\]]*)\];", _js())
    assert m, "the console does not name the stance vocabulary once"
    offered = {int(v) for v in re.findall(r"-?\d+", m.group(1))}
    assert offered == router_accepts, (
        f"the chooser offers {sorted(offered)} and the router accepts "
        f"{sorted(router_accepts)}")

    # The stance is an ASSERTION (router docstring), so the chooser shows
    # what the assertion rests on, and a save re-reads the matrix so the
    # router's warnings render through the pane's existing path.
    assert "Admiralty" in block, "the chooser does not show the assertion's grading"
    assert "loadAch()" in block, "a saved stance does not re-render the ranking"


def test_there_is_one_labelOf_and_it_never_returns_null():
    """There is one top-level `function labelOf(` and it never returns null.

    Function declarations hoist and the LAST wins, so with two (the inspector's, falling back to the
    projection list then a short id, and the merge panel's, entity list only, else `null`) every
    caller written against the first would print "ego of null" for a node the projection knew and the
    entity list did not, with nothing crashing.

    The fallback order is asserted through the helper it delegates to: the entity list first (richer
    record), then the projection, then a placeholder that says what it is standing in for. Callers do
    not paper over the null with `|| shortId(...)`: a guard against a value the function can no longer
    return is a false clue for the next reader.
    """
    js = _js()
    declared = re.findall(r"^function labelOf\(", js, flags=re.M)
    assert len(declared) == 1, (
        f"{len(declared)} top-level labelOf declarations; the last one wins "
        f"and every caller written against the other is wrong")

    start = js.index("function labelOf(")
    body = js[start:js.index("\n}", start)]
    assert "return null" not in body, "labelOf can still return null"
    assert "nodeById(" in body, "labelOf no longer consults both node lists"
    assert "shortId(" in body, "the placeholder no longer carries the id"

    nb_start = js.index("function nodeById(")
    nb = js[nb_start:js.index("\n}", nb_start)]
    assert nb.index("state.nodes") < nb.index("state.gnodes"), (
        "the projection is consulted before the entity list, so the poorer "
        "record wins")

    guarded = [line.strip() for line in js.splitlines()
               if re.search(r"labelOf\([^()]*\)\s*\|\|", line)]
    assert not guarded, (
        "a caller still guards labelOf against a null it cannot return:\n"
        + "\n".join("  " + g for g in guarded))


def test_the_login_code_field_admits_a_recovery_code():
    """`AuthService.authenticate` accepts a recovery code in `totp_code` (`recovery.looks_like_code`
    tells the two apart by shape), so the sign-in field must admit one, not be
    `maxlength="6" pattern="[0-9]{6}" inputmode="numeric"`. Otherwise the escape hatch for a skewed
    clock exists on the server and cannot be typed into the client.

    The shape is taken from the recovery module, not copied: a second copy of the alphabet or the
    group length is how the field drifts again.
    """
    from noctornal_api.security import recovery

    tag = re.search(r'<input id="login-totp"[^>]*>', _html(), flags=re.S)
    assert tag, "the sign-in code field is gone"
    tag = tag.group(0)
    maxlength = re.search(r'maxlength="(\d+)"', tag)
    pattern = re.search(r'pattern="([^"]+)"', tag)
    assert maxlength and pattern, "the field no longer states its shape"

    code = recovery.generate_code()
    assert len(code) <= int(maxlength.group(1)), (
        f"maxlength={maxlength.group(1)} truncates a {len(code)}-character "
        f"recovery code before it reaches the server")
    assert re.fullmatch(pattern.group(1), code), (
        f"pattern={pattern.group(1)!r} rejects the recovery code {code!r}")
    # The six-digit fast path still matches.
    assert re.fullmatch(pattern.group(1), "123456")

    # The alphabet has letters in it, so a numeric keyboard would hide the
    # keys the code is made of. Derived from the module, so a future
    # all-digit alphabet may bring the numeric hint back.
    if any(c.isalpha() for c in recovery._ALPHABET):
        assert 'inputmode="numeric"' not in tag, (
            "a numeric on-screen keyboard cannot type a recovery code")

    html = _html()
    start = html.index('id="login-totp-help"')
    help_text = re.sub(r"\s+", " ", html[start:html.index("</span>", start)])
    assert "recovery code" in help_text.lower(), (
        "the help text does not say a recovery code works here")


def test_the_console_holds_no_token_in_web_storage_and_speaks_the_cookie_contract():
    """The server sets `__Host-session` (HttpOnly) and `__Host-csrf` on every login, and
    `deps.session_token` honours the pair with an `x-csrf-token` double-submit, so the console keeps no
    bearer token in `sessionStorage`, where any script on the origin could read it for the life of the
    tab.

    Both halves of the contract, from one file: no storage write, the header and cookie names the
    console uses are the ones deps.py declares, requests carry credentials, and the `#token=` hand-off
    from `bootstrap.py session` is exchanged for the cookie session through a route auth.py defines.
    """
    js = _js()
    stored = [
        (i, line.strip()) for i, line in enumerate(js.splitlines(), 1)
        for m in [re.search(r"(session|local)Storage\.setItem\(\s*([^,]+),", line)]
        if m and "token" in m.group(2).lower()
    ]
    assert not stored, (
        "the console still writes the session token to web storage:\n"
        + "\n".join(f"  app.js:{i}: {line}" for i, line in stored))
    assert "sessionStorage.getItem(TOKEN_KEY)" not in js

    from noctornal_api.http.deps import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
    assert f"'{CSRF_HEADER}'" in js, "the console does not send the CSRF header"
    assert f"'{CSRF_COOKIE}'" in js, "the console does not read the CSRF cookie"
    assert f"'{SESSION_COOKIE}'" not in js, (
        "the session cookie is HttpOnly; a console that names it is trying "
        "to read it")

    start = js.index("async function _fetch(")
    fetch_body = js[start:js.index("\n}", start)]
    assert "credentials: 'same-origin'" in fetch_body, (
        "requests are sent without credentials, so the cookie never travels")

    auth_src = (SRC / "http" / "routers" / "auth.py").read_text(encoding="utf-8")
    assert '@router.post("/cookie"' in auth_src, (
        "auth.py has no route that turns a bearer session into the cookie pair")
    assert "'/auth/cookie'" in js, (
        "the console never exchanges a #token= hand-off for the cookie session")


# Cookie session contracts across app.js and the API. Each test reads BOTH sides, because a defect
# here is two halves wrong together.


def _js_function(name: str) -> str:
    """The body of a top-level function, comments included, closed on the
    first `}` at column 0 after its declaration."""
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start)]


def test_a_refused_hand_off_or_sign_out_never_reports_what_the_server_did_not_do():
    """A refused hand-off or sign-out never reports what the server did not do.

    `_fetch` must not end the session on a 401 that is not a verdict on the request's own credential
    (the speculative `POST /auth/cookie` exchange). `endSession` deletes the readable `__Host-csrf`
    but cannot touch the HttpOnly half, `boot()` would then show the app on `GET /auth/me` (which the
    session cookie alone satisfies), every write would be a 403 "missing or invalid CSRF token", and
    `doLogout` would show the sign-in form while the server kept the session, which a reload restores.
    A stale `bootstrap.py session` link opened in a signed-in tab is enough to reach it.

    Three halves, read together: the routes whose 401 `_fetch` treats as a verdict on the credential in
    the request are exactly the credential checks `routers/auth.py` defines; `startApp` refuses a
    session that has no readable half and no in-memory token; and `doLogout` ends the session only
    after the server accepted the sign-out.
    """
    js = _js()
    m = re.search(r"const _CREDENTIAL_CHECKS = new Set\(\[([^\]]*)\]\);", js)
    assert m, "the console no longer names the 401 exemptions in one place"
    exempt = set(re.findall(r"'([^']+)'", m.group(1)))
    assert exempt == {"/auth/login", "/auth/cookie"}, exempt
    auth_src = (SRC / "http" / "routers" / "auth.py").read_text(encoding="utf-8")
    for route in exempt:
        suffix = route.removeprefix("/auth")
        assert re.search(rf'@router\.post\("{re.escape(suffix)}"', auth_src), (
            f"{route} is exempt from ending the session but auth.py does "
            f"not define it")
    fetch_body = _js_function("_fetch")
    assert "_CREDENTIAL_CHECKS.has(path)" in fetch_body
    assert "path !== '/auth/login'" not in fetch_body, (
        "the exemption is still a single hard-coded route")

    guard = re.search(r"^function halfSession\(\) \{(.*)\}$", js, flags=re.M)
    assert guard, "the console has no one definition of a half session"
    assert "csrfCookie()" in guard.group(1) and "state.token" in guard.group(1)
    start_app = _js_function("startApp")
    assert "halfSession()" in start_app, "startApp shows the app on a half session"
    assert start_app.index("halfSession()") < start_app.index("show($('view-app'), true)"), (
        "the app is shown before the half-session check")
    assert "endSession(HALF_SESSION_TITLE" in start_app, (
        "a refused half session is not explained to the analyst")

    logout = _js_function("doLogout")
    assert "local sign-out regardless" not in logout
    assert "} catch (err)" in logout and "banner(" in logout, (
        "doLogout still swallows the server's refusal")
    assert logout.index("endSession(") > logout.index("} catch (err)"), (
        "doLogout ends the session before the server accepted the sign-out")
    catch_block = logout[logout.index("} catch (err)"):logout.index("endSession(")]
    assert "return;" in catch_block, "a refused sign-out still falls through to endSession"


def test_a_fragment_token_never_replaces_the_session_the_browser_holds():
    """`adoptSessionFromFragment` must not replace a session the browser already holds.

    `deps.session_token` prefers the bearer, so a link of the documented deep-link shape carrying
    another account's token, opened by a signed-in analyst, would swap the cookie under every tab they
    have open. Both halves: the console asks `/auth/me` on the cookie BEFORE it exchanges and keeps a
    usable session it finds, and `adopt_cookie` refuses a cookie session for a different account with
    409 and an audit row, the line that holds when the console is wrong (`test_auth_cookie_http_pg`
    drives that refusal against Postgres).

    Also holds the header comment to the code. A form sign-in hands the page nothing (login answers
    204); the `#token=` hand-off is the one thing that fills `state.token`, and the socket's first
    frame is where that token is spent, on a host whose browser refused the Secure pair. So the header
    must say where a hand-off token is held and what still spends it, not claim that nothing in this
    page is readable.
    """
    js = _js()
    body = _js_function("adoptSessionFromFragment")
    probe = body.index("api('/auth/me')")
    exchange = body.index("'/auth/cookie'")
    assert probe < exchange, "the exchange runs before the browser's session is checked"
    assert "halfSession()" in body[probe:exchange], (
        "a live session with its readable half is not the condition for keeping it")
    assert "state.token = token" in body and body.index("state.token = token") > probe, (
        "the handed-over token is put in memory before the browser's session is checked")

    header = js[:js.index("'use strict'")]
    assert "cannot lift the token" not in header, (
        "the header still claims the credential is unreadable from script")
    # Whitespace-flattened before the match, because this is prose in a block comment and prose gets
    # rewrapped: an assertion about what a comment SAYS must not double as a detector of where its
    # lines end.
    flat = re.sub(r"\s+", " ", header)
    assert "state.token" in flat and "first frame" in flat, (
        "the header does not say where a hand-off token is held and what "
        "still spends it")

    auth_src = (SRC / "http" / "routers" / "auth.py").read_text(encoding="utf-8")
    fn = auth_src[auth_src.index("def adopt_cookie("):auth_src.index("\ndef _set_session_cookies")]
    assert "409" in fn and "AUTH_COOKIE_ADOPT_REFUSED" in fn, (
        "adopt_cookie does not refuse a cookie session for another account")
    assert "request.cookies.get(SESSION_COOKIE)" in fn, (
        "adopt_cookie never looks at the cookie the browser presents")
    assert "strict-bound" not in fn, (
        "the docstring claims strict binding unconditionally; it is "
        "NOCTORNAL_SESSION_STRICT_BINDING-gated")


def test_the_sample_download_presents_the_credential_the_sample_origin_preflight_admits():
    """The Lab download presents no custom header, which keeps it a SIMPLE cross-origin request.

    The Lab download is the console's one cross-origin request. The sample process answers the
    preflight with `Access-Control-Allow-Headers: authorization` alone and sends no `Allow-Credentials`,
    so a CSRF header would fail the preflight and the pane would report "did not complete" for a request
    the server never saw. The console presents no header at all: 0061's download ticket is redeemed as
    a form body, and a ticket cannot be a header because `authorization` is the only one this preflight
    admits. The header set app.py admits is read from app.py, and what the console must NOT send is
    read from the console.
    """
    app_src = (SRC / "http" / "app.py").read_text(encoding="utf-8")
    m = re.search(r'"Access-Control-Allow-Headers":\s*"([^"]+)"', app_src)
    assert m, "app.py no longer answers the download preflight"
    admitted = {h.strip().lower() for h in m.group(1).split(",")}
    assert admitted == {"authorization"}, admitted

    body = _js_function("downloadSample")
    assert "fetchFromSampleOrigin(" in body, "the download no longer goes to the sample origin"
    assert "credentials: 'omit'" in body
    cross = body[body.index("fetchFromSampleOrigin("):]
    for banned in ("headers", "authHeaders(", "Authorization", "state.token"):
        assert banned not in cross, (
            f"the cross-origin download sends {banned!r}: the sample origin's "
            f"preflight admits `authorization` alone, so any header at all "
            f"turns a simple request into one this deployment refuses before "
            f"the server sees it")

# ---------------------------------------------------------------------------
# The live socket's policy close is honoured by the client that receives it
# ---------------------------------------------------------------------------

def test_the_live_client_stops_on_the_policy_close_the_server_documents():
    """live.py sends 1008 for "the server decided" and says the console stops reconnecting on it; the
    console's close handler must therefore read the close code and return on 1008 before scheduling a
    retry, or it retries six times and looks like an attack in the audit log.
    """
    src = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
    js = (src / "http" / "static" / "app.js").read_text(encoding="utf-8")
    live = (src / "http" / "routers" / "live.py").read_text(encoding="utf-8")

    start = js.index("ws.addEventListener('close'")
    handler = js[start:start + 1200]
    assert re.search(r"addEventListener\('close',\s*\(event\)", handler), (
        "the close handler takes no event, so it cannot read the close code")
    stop = re.search(r"event\.code\s*===\s*1008\)\s*return", handler)
    retry = handler.index("setTimeout(connectLive")
    assert stop and stop.start() < retry, (
        "the handler must return on 1008 BEFORE it schedules a reconnect")

    assert "_CLOSE_POLICY = 1008" in live
    assert re.search(r"stops\s+reconnecting on this code", live.replace("#:", "")), (
        "live.py must state the client's real policy for 1008")
    assert "backs off\n#: on any close" not in live, (
        "live.py still says the client backs off on ANY close")


def test_the_palette_offers_every_pane_the_rail_has():
    """`TAB_NAMES` is the command palette's "Go to" list. It is held to the rail's `data-tab` set, in
    rail order, so the next pane cannot be added to one and not the other."""
    rail = re.findall(r'data-tab="([a-z-]+)"', _html())
    assert len(rail) >= 17, rail
    block = re.search(r"const TAB_NAMES = \[(.*?)\];", _js(), re.S)
    assert block, "app.js has lost TAB_NAMES"
    palette = re.findall(r"\['([a-z-]+)',", block.group(1))
    assert palette == rail, (
        "the palette's Go-to list and the rail disagree:\n"
        f"  rail:    {rail}\n  palette: {palette}")


# The console asks for no credential it can read. The live socket takes `__Host-session` itself, which
# is HttpOnly and cannot be lifted from this page, and the Lab download takes a one-shot ticket minted
# on THIS origin under the cookie session: readable by the page, and deliberately so, but worth one
# archive for sixty seconds rather than the case file for the life of a session.
#
# Every test below reads both sides, because each of these contracts exists only in the gap between
# two files and each half is silently useless alone: a console that opens a socket the server would
# refuse reports "not live" and nothing else, and a server that accepts a cookie no client sends is a
# feature nobody reaches.


def _live_py() -> str:
    return (SRC / "http" / "routers" / "live.py").read_text(encoding="utf-8")


def _samples_router() -> str:
    return (SRC / "http" / "routers" / "samples.py").read_text(encoding="utf-8")


def test_the_live_socket_opens_on_the_cookie_and_is_not_gated_on_a_token():
    """The socket reads `__Host-session` off the upgrade, so `connectLive` must not refuse to open one
    for a session that holds only the cookie. A `connectLive` that still gates on `state.token` is a
    console that never goes live after a reload and says only "not live".

    The frame's `token` survives as a FALLBACK and is sent only when the tab actually holds one (a
    console the browser refused the Secure cookies on; `scripts/bootstrap.py session` in a shell).
    Sending it unconditionally would send `null` on every socket, a token field this page has no reason
    to fill.
    """
    live = _live_py()
    assert re.search(
        r"token\s*=\s*ws\.cookies\.get\(SESSION_COOKIE\)\s*or\s*frame_token",
        live), (
        "live.py no longer prefers the session cookie over the first "
        "frame, so a cookie-only console cannot authenticate this socket")

    body = _js_function("connectLive")
    preamble = body[:body.index("new WebSocket(")]
    assert "state.token" not in preamble, (
        "connectLive still decides whether to open the socket by looking at "
        "the in-memory token; the credential is the cookie, which this "
        "script cannot see")
    assert "const hello = { case_id: state.caseId };" in body, (
        "the hello no longer carries the case id, which has nowhere else to go")
    assert "if (state.token) hello.token" in body, (
        "the frame token is unconditional again: a signed-in browser would "
        "send a null token field it has no reason to fill")

    js = _js()
    assert "still needs the sign-in" not in js, (
        "the console still explains that the live channel needs the sign-in "
        "token; it has not since 2026-09-10, and an honest-sounding stale "
        "sentence is worse than the plain 'not live' the dot carries")
    assert re.search(r"function liveStatus\(state_\)", js), (
        "liveStatus takes a per-call reason again -- the only caller that "
        "ever passed one was the refusal that has been deleted")


def test_the_policy_close_still_stops_the_client_that_now_reconnects_more():
    """The 1008 policy close still stops the client.

    `connectLive` opens a socket in many situations, so the one close code that means "the server has
    decided" must return before a retry: otherwise the console retries six times against a hub that
    refused it, which reads as an attack in the audit log. The retry gate below it keys on the session,
    not `state.token`: a null token does not mean "no session" now that the socket takes the cookie,
    and a token gate would make the reconnect the one thing still refusing a cookie-only session.
    """
    body = _js_function("connectLive")
    stop = re.search(r"event\.code\s*===\s*1008\)\s*return", body)
    assert stop, "the close handler no longer returns on the policy close"
    assert stop.start() < body.index("setTimeout(connectLive"), (
        "the handler schedules a reconnect before it reads the close code")
    assert "!signedIn() || _wsRetry >= 6" in body, (
        "the retry gate is not the session; `state.token` here would stop a "
        "cookie-only console from ever reconnecting")
    assert "!state.token ||" not in body
    assert "_CLOSE_POLICY = 1008" in _live_py()


def test_the_lab_download_crosses_the_origin_on_a_ticket_and_not_on_the_session():
    """0061. The console mints a one-shot ticket on the application origin and spends it at the sample
    origin, so the credential that crosses is good for one sample, one redemption and sixty seconds,
    not the session token.

    Both sides, because the shape of the redemption is a contract: the route takes the ticket as a FORM
    field, and `application/x-www-form-urlencoded` is CORS-safelisted, so the redemption is a simple
    cross-origin request. A console that sent JSON would need `content-type` added to
    `app._preflight`'s `Access-Control-Allow-Headers` and would fail as "the request did not complete"
    until somebody did.

    The ticket is never assembled into a URL, on either side. A query string reaches the access log,
    the browser history and the `Referer`, and this one buys a live binary.
    """
    samples_src = _samples_router()
    assert '@router.post("/{sample_id}/download-ticket"' in samples_src, (
        "the mint route is gone; the console has nothing to mint from")
    assert re.search(r"ticket: str \| None = Form\(", samples_src), (
        "the download no longer takes a ticket in the form body, so the "
        "console's redemption is either refused or preflighted")
    assert "download_url: str" in samples_src, (
        "the mint no longer returns the absolute URL to redeem at, and a "
        "console assembling one from location.origin is how this pane came "
        "to fetch the application origin in the first place")

    body = _js_function("downloadSample")
    mint = body.index("'/download-ticket'")
    fetch = body.index("fetchFromSampleOrigin(")
    assert mint < fetch, "the console fetches the archive before it has a ticket"
    assert "fetchFromSampleOrigin(minted.download_url" in body, (
        "the redemption goes somewhere other than the URL the server minted")
    assert "new URLSearchParams({ ticket: minted.ticket })" in body, (
        "the ticket does not travel as a form body: JSON would need a "
        "content-type the sample origin's preflight does not admit")
    assert "JSON.stringify" not in body

    assert not re.search(r"[?&]ticket=", _js()), (
        "a ticket was put in a query string; it is a credential, and a URL "
        "reaches the access log, the history and the Referer")


def test_the_download_ticket_is_minted_on_the_path_that_carries_the_double_submit():
    """The mint is reached the ordinary way: `api()`, which sends the cookie and copies `__Host-csrf`
    into `x-csrf-token` on an unsafe method. Three files have to agree for that to be true: the console
    must POST through `api()`, `deps` must count POST as unsafe, and the route must be declared POST. A
    GET mint would be exempt from the double-submit while remaining something a prefetcher or a link
    scanner can fire.
    """
    body = _js_function("downloadSample")
    assert "await api('/samples/'" in body, (
        "the ticket is not minted through api(), so it does not carry the "
        "cookie session's double-submit header")
    assert "fetchFromSampleOrigin(" in body
    assert body.index("await api('/samples/'") < body.index("fetchFromSampleOrigin("), (
        "the mint is not the same-origin leg")
    mint_call = body[body.index("await api('/samples/'"):body.index("} catch (err)")]
    assert "method: 'POST'" in mint_call, "the mint is not an unsafe method"

    headers = _js_function("authHeaders")
    assert "headers[CSRF_HEADER] = csrf" in headers
    assert "/^(GET|HEAD|OPTIONS)$/i" in headers, (
        "authHeaders no longer decides the CSRF header by method")

    from noctornal_api.http.deps import _UNSAFE_METHODS
    assert "POST" in _UNSAFE_METHODS, (
        "deps no longer demands the double-submit on a POST, so the mint "
        "is reachable from another origin's page with the cookie alone")

    samples_src = _samples_router()
    assert '@router.get("/{sample_id}/download-ticket"' not in samples_src
    fn = samples_src[samples_src.index("def mint_download_ticket("):
                     samples_src.index('"""A one-shot')]
    assert "Depends(_REQUIRE_DOWNLOAD)" in fn, (
        "the mint no longer states the download's own permission gate")
    assert "Depends(require_step_up)" in fn, (
        "the mint is not step-up gated, so the fresh second factor the "
        "download has always demanded is no longer asked of anybody")
    assert '_REQUIRE_DOWNLOAD = require_global("sample.download")' in samples_src


def test_both_legs_of_the_download_report_the_servers_own_sentence():
    """A refusal from either leg of the download reaches the analyst as the server wrote it.

    The two legs fail for different reasons and only the server knows which: the mint refuses an
    expired step-up, a clearance that does not reach the sample, or a misconfigured origin split; the
    redemption refuses a ticket that has been spent, has expired, or was issued for another sample.

    `refusalText` puts `detail` first. The cross-origin leg does not come through `api()`, so its
    refusal is not an `ApiError` until this code makes one, and a hand-rolled second spelling of "it
    was refused" on that path is the divergence `refusalText` exists to prevent.
    """
    body = _js_function("downloadSample")
    assert body.count("refusalText(") >= 2, (
        "one of the two legs reports a refusal without the server's sentence")
    assert "new ApiError(res.status, p.title, p.detail)" in body, (
        "the cross-origin refusal never becomes an ApiError, so refusalText "
        "cannot read the detail the sample origin sent")
    assert body.index("refusalText(") < body.index("fetchFromSampleOrigin("), (
        "the mint's refusal does not go through refusalText")

    helper = _js_function("refusalText")
    assert "return detail + (context" in helper, (
        "refusalText no longer puts the server's detail first")


def test_a_sign_in_hands_the_browser_a_cookie_and_nothing_it_can_read(monkeypatch):
    """`POST /auth/login` answers 204 with the cookie pair and NO body, so a sign-in hands the browser
    a cookie and nothing it can read. With the raw token in the response, `HttpOnly` would buy nothing:
    any script with a foothold on this origin could read the credential out of the login response or
    `state.token`.

    Held from three sides, because a regression would look different from each. The OPENAPI document
    is the contract a client is written against, and a `LoginResponse` reappearing there is the change
    to catch. The DECORATOR is what that document is generated from, asserted separately so a failure
    says which of the two moved. And the CONSOLE must not read a token off that response: `_fetch`
    returns null for a 204, so such an assignment throws a TypeError on every form sign-in and reports
    a completed sign-in as an unexpected error.

    `state.token` itself is deliberately NOT asserted away. The `#token=` hand-off still fills it
    (`adoptSessionFromFragment`), and `scripts/bootstrap.py session` still mints a bearer directly;
    what is excluded is LOGIN handing one out.
    """
    import json

    # The neighbours' environment: enough for `create_app()` to build, and
    # a DSN in TEST-NET-1 that nothing here ever dials. No route is called
    # -- the document and the route table are read off the object.
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@192.0.2.1:5432/x")
    from noctornal_api.http.app import API_PREFIX, create_app
    app = create_app()
    schema = app.openapi()

    path = f"{API_PREFIX}/auth/login"
    responses = schema["paths"][path]["post"]["responses"]
    assert "200" not in responses, (
        "the login route declares a 200 again; a sign-in that answers with "
        "a body is a sign-in that hands the page a readable credential")
    assert "204" in responses, responses
    assert "content" not in responses["204"], (
        f"the 204 declares a body: {responses['204']!r}")
    assert "LoginResponse" not in json.dumps(schema), (
        "LoginResponse is back in the OpenAPI document")

    auth_src = (SRC / "http" / "routers" / "auth.py").read_text(encoding="utf-8")
    assert 'status_code=204' in auth_src[auth_src.index('@router.post("/login"'):
                                         auth_src.index("def login(")], (
        "the login route does not declare 204; the document above is "
        "generated from this decorator and would follow it back to a body")
    assert "class LoginResponse" not in auth_src
    assert "_set_session_cookies(response, token)" in auth_src, (
        "the login no longer sets the cookie pair, which is now the whole "
        "of what a successful sign-in produces")

    body = _js_function("doLogin")
    assert not re.search(r"^\s*state\.token\s*=", body, re.M), (
        "doLogin assigns state.token again. The login response has no body "
        "to take one from -- `_fetch` returns null for a 204 -- so the "
        "assignment throws and the analyst is told 'Unexpected error' for a "
        "sign-in the server completed")
    assert not re.search(r"^\s*const\s+\w+\s*=\s*await api\('/auth/login'", body, re.M), (
        "doLogin binds the login response to a name; there is nothing in it")
