"""What is read once sits behind an "i", and the canvas key and shortcuts sit behind two buttons.

An explanation that is not needed on every visit is not on the screen: it opens from a small "i" on hover, focus or
a press, and a line of help marked `fold` is tucked behind one on the heading it explains. The words stay in the
page, so a test, a screen reader and the bubble all read them. A line that protects somebody (a warning, a refusal,
a consequence) is never folded.

Pure: no database, no browser. The painters' source is read, and the fold search runs under node against a small
stand-in for the DOM (skipped where node is absent).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

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


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    guess = r"C:\Program Files\nodejs\node.exe"
    return guess if os.path.exists(guess) else None


# ---------------------------------------------------------------------------
# The bubble
# ---------------------------------------------------------------------------

def test_the_bubble_is_written_as_text_and_never_as_markup():
    for name in ("infoTip", "showTip", "foldHelp"):
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
    for rule in (".info, .info-glyph {", ".tip-bubble {", ".tip-src { display: none !important; }",
                 ".info-link {", ".panel-pop {"):
        assert rule in css, f"{rule} is gone"
    assert ".info::after { content: ''; position: absolute; inset: -5px; }" in css, (
        "the 16px circle has no larger press target")
    bubble = css[css.index(".tip-bubble {"):]
    bubble = bubble[:bubble.index("}")]
    assert "pointer-events: none" in bubble, "the bubble would take the pointer from what is under it"


# ---------------------------------------------------------------------------
# Folded help lines
# ---------------------------------------------------------------------------

_FOLDED = re.compile(r'<(p|div)\b([^>]*\bclass="([^"]*\bfold\b[^"]*)"[^>]*)>(.*?)</\1>', re.S)


def _folded() -> list[tuple[str, str, str]]:
    """(tag, class, text) of every element index.html marks `fold`."""
    out = []
    for m in _FOLDED.finditer(_html()):
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(4))).strip()
        out.append((m.group(1), m.group(3), text, m.group(2)))
    return out


def test_a_folded_line_is_help_or_a_hint_and_has_words_or_an_id_for_a_script_to_fill():
    found = _folded()
    assert len(found) > 40, "the help lines are no longer folded"
    for tag, cls, text, attrs in found:
        assert re.search(r"\b(help|hint)\b", cls), f"{tag}.{cls} is folded but is not a help line"
        assert text or 'id="' in attrs, f"an empty folded line with no id for a script to fill: {cls}"


def test_a_line_that_protects_somebody_is_never_folded():
    """A warning, a refusal or a consequence stays on screen: folding it would make it optional reading."""
    for _tag, cls, text, _attrs in _folded():
        assert "warn" not in cls.split(), f"a warning is folded: {text[:80]}"
        assert "refused" not in cls.split() and "danger" not in cls.split(), text[:80]


def test_every_folded_line_keeps_its_element_so_nothing_is_lost():
    fold = _fn("foldHelp")
    assert "classList.add('tip-src')" in fold, "a folded line is removed or hidden by some other means"
    assert "removeChild" not in fold and ".remove()" not in fold
    assert "aria-describedby" in fold, "a screen reader is no longer given the folded words"
    assert "foldHelp();" in _fn("wire")


_FOLD_HARNESS = r"""
// A stand-in for the few DOM members foldAnchor and its selectors use.
class Fake {
  constructor(tag, cls, attrs) {
    this.tagName = tag.toUpperCase();
    this.classes = (cls || '').split(/\s+/).filter(Boolean);
    this.attrs = attrs || {};
    this.dataset = {};
    this.children = [];
    this.parentElement = null;
    this.id = this.attrs.id || '';
  }
  add(...kids) {
    for (const k of kids) { k.parentElement = this; this.children.push(k); }
    return this;
  }
  get previousElementSibling() {
    const sibs = this.parentElement ? this.parentElement.children : [];
    const i = sibs.indexOf(this);
    return i > 0 ? sibs[i - 1] : null;
  }
  matches(selector) {
    return selector.split(',').some((raw) => {
      const sel = raw.trim();
      const attr = /^\[(\w+)="([^"]*)"\]$/.exec(sel);
      if (attr) return this.attrs[attr[1]] === attr[2];
      if (sel.startsWith('.')) return this.classes.includes(sel.slice(1));
      return this.tagName === sel.toUpperCase();
    });
  }
  querySelectorAll(selector) {
    const out = [];
    const walk = (n) => { for (const c of n.children) { if (c.matches(selector)) out.push(c); walk(c); } };
    walk(this);
    return out;
  }
  closest(selector) {
    for (let n = this; n; n = n.parentElement) if (n.matches(selector)) return n;
    return null;
  }
}
const $ = (id) => (id === 'target' ? target : null);
const target = new Fake('span', 'label', { id: 'target' });
const FOLD_HEADS = 'h1, h2, h3, h4, .pane-title, .h-sm, .h-md, .h-xs, legend, .label, .eyebrow';
""" + "\n__FOLD_ANCHOR__\n" + r"""
const help = (cls) => new Fake('p', cls || 'help fold');
const out = {};

// A heading just before the line is its anchor.
let h = new Fake('h2', 'h-sm'); let p = help();
new Fake('section', 'pane', { role: 'tabpanel' }).add(h, p);
out.heading = foldAnchor(p) === h;

// A heading inside the sibling before it, the last one when there are several.
let row = new Fake('div', 'row'); const l1 = new Fake('span', 'label'); const l2 = new Fake('span', 'label');
row.add(l1, l2); p = help(); h = new Fake('h3', 'h3');
new Fake('section', 'pane').add(h, row, p);
out.lastInside = foldAnchor(p) === l2;

// The pane before this one is never searched: no heading here means no anchor.
const first = new Fake('section', 'pane'); first.add(new Fake('h2', 'pane-title'));
p = help(); const second = new Fake('section', 'pane'); second.add(p);
new Fake('div', 'work').add(first, second);
out.fenced = foldAnchor(p) === null;

// A sub-pane is a fence too.
const sub = new Fake('div', 'subpane'); p = help(); sub.add(p);
new Fake('section', 'pane').add(new Fake('h2', 'h-sm'), sub);
out.subpane = foldAnchor(p) === null;

// A line inside a disclosure does not borrow a label from outside it.
const det = new Fake('details', 'card'); p = help(); det.add(new Fake('summary', ''), p);
new Fake('section', 'pane').add(new Fake('label', 'field').add(new Fake('span', 'label')), det);
out.disclosure = foldAnchor(p) === null;

// data-tip-for names the anchor; data-fold="inline" asks for none.
p = help(); p.dataset.tipFor = 'target'; out.named = foldAnchor(p) === target;
p = help(); p.dataset.fold = 'inline'; new Fake('section', 'pane').add(new Fake('h2', 'h-sm'), p);
out.inline = foldAnchor(p) === null;
console.log(JSON.stringify(out));
"""


def test_the_fold_search_stays_inside_the_pane_and_the_disclosure_it_is_in():
    node = _node()
    if not node:
        pytest.skip("node is not installed here; the static checks still ran")
    script = _FOLD_HARNESS.replace("__FOLD_ANCHOR__", _fn("foldAnchor"))
    res = subprocess.run([node, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert res.returncode == 0, res.stderr
    got = json.loads(res.stdout)
    assert got == {"heading": True, "lastInside": True, "fenced": True, "subpane": True,
                   "disclosure": True, "named": True, "inline": True}, got


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
