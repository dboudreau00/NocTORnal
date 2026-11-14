"""What is read once sits behind an "i", and the canvas key and shortcuts sit behind two buttons.

An explanation that is not needed on every visit is not on the screen: it opens from a small "i" on hover, focus or
a press. The words stay in the page, so a test, a screen reader and the bubble all read them.

Pure: no database, no browser. The painters' source is read.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
APP_JS = STATIC / "app.js"
APP_CSS = STATIC / "app.css"
INDEX = STATIC / "index.html"


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}\n", start) + 2]


# ---------------------------------------------------------------------------
# The bubble
# ---------------------------------------------------------------------------

def test_the_bubble_is_written_as_text_and_never_as_markup():
    for name in ("infoTip", "showTip"):
        body = _fn(name)
        assert "innerHTML" not in body and "insertAdjacentHTML" not in body, name
    show = _fn("showTip")
    assert ".textContent = text" in show, "the bubble no longer takes its words as text"
    assert "role', 'tooltip'" in show
    assert "aria-description" in _fn("infoTip")


def test_the_bubble_opens_on_hover_focus_and_press_and_closes_on_esc_scroll_and_resize():
    wire = _fn("wireTips")
    for event in ("'mouseover'", "'mouseout'", "'focusin'", "'focusout'", "'click'", "'keydown'",
                  "'scroll'", "'resize'"):
        assert event in wire, f"the bubble does not listen for {event}"
    assert "'Escape'" in wire
    assert "tipBubble.pinned" in wire, "a press no longer holds the bubble open"
    assert "wireTips();" in _fn("wire")


def test_the_bubble_stays_inside_the_window_and_flips_below_when_there_is_no_room():
    show = _fn("showTip")
    assert "window.innerWidth" in show and "clamp(" in show
    assert "above" in show and "r.bottom" in show


def test_the_bubble_and_its_trigger_are_styled_from_the_theme_alone():
    css = APP_CSS.read_text(encoding="utf-8")
    for rule in (".info {", ".tip-bubble {", ".tip-src { display: none !important; }",
                 ".panel-pop {"):
        assert rule in css, f"{rule} is gone"
    assert ".info::after { content: ''; position: absolute; inset: -5px; }" in css, (
        "the 16px circle has no larger press target")
    bubble = css[css.index(".tip-bubble {"):]
    bubble = bubble[:bubble.index("}")]
    assert "pointer-events: none" in bubble, "the bubble would take the pointer from what is under it"


# ---------------------------------------------------------------------------
# The canvas key and the shortcuts
# ---------------------------------------------------------------------------

def test_the_canvas_key_and_the_shortcuts_are_closed_panels_a_button_opens():
    html = _html()
    for button, panel in (("btn-key", "legend-more"), ("btn-keys", "keys-more")):
        m = re.search(rf'<button id="{button}"[^>]*>', html)
        assert m, f"{button} is gone"
        assert f'aria-controls="{panel}"' in m.group(0) and 'aria-expanded="false"' in m.group(0)
        assert "panel-btn" in m.group(0)
        pm = re.search(rf'<div id="{panel}"[^>]*>', html)
        assert pm and "panel-pop" in pm.group(0) and " hidden" in pm.group(0), f"{panel} opens by itself"
    wire = _fn("wirePanels")
    assert "'Escape'" in wire and "closeAll(" in wire
    assert "closest('.panel-pop, .panel-btn')" in wire, "a press elsewhere no longer closes a panel"
    assert "wirePanels();" in _fn("wire")


def test_the_size_key_is_drawn_when_its_panel_opens_because_a_hidden_canvas_has_no_size():
    wire = _fn("wirePanels")
    assert "noteSizeKey(state.graph)" in wire and "sizeKeyShown = ''" in wire


def test_the_key_keeps_the_entity_types_in_view_and_every_other_mark_one_press_away():
    html = _html()
    legend = html[html.index('<div class="legend"'):html.index('id="proj-readout"')]
    types = legend[:legend.index('id="btn-key"')]
    for name in ("Persona", "Person", "Group", "Victim", "Infra / comms", "Finance", "Malware", "Context"):
        assert name in types, f"{name} is not in the row that stays in view"
    more = legend[legend.index('id="legend-more"'):]
    for name in ("vouch / positive", "dispute / negative", "dashed = inferred", "hollow = no exhibit",
                 "bead = tie with no exhibit", "proposal in Triage or tie to review", "selected", "pinned",
                 "path anchor", "ego centre", "opacity = confidence", 'id="size-key"'):
        assert name in more, f"{name} is not in the key panel"
