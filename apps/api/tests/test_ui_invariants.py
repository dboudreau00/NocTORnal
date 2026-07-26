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
    """
    js = _js()
    assert "function withSafeLabel" in js
    assert "nodes.map(withSafeLabel)" in js, "the entity list is unsanitised"
    assert "(g.nodes || []).map(withSafeLabel)" in js, \
        "the sociogram projection is unsanitised"


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


@pytest.mark.parametrize("element_id", sorted({
    # Ids app.js addresses by name. A typo in either file is a silent no-op
    # at boot -- $() returns null and the listener is never attached, so
    # the button simply does nothing when clicked, with no error anywhere.
    "smp-policy", "smp-state", "smp-refresh", "smp-counts", "smp-list",
    "smp-empty", "smp-detail", "smp-detail-title", "smp-detail-body",
    "smp-close", "smp-file", "smp-case", "smp-class", "smp-note",
    "smp-submit", "smp-submit-msg", "smp-origin", "samples-badge",
    "busy", "keys-scrim", "keys-close", "keys-palette",
}))
def test_element_ids_exist(element_id: str):
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
