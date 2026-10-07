"""The first-sign-in walkthrough and the Help entry, held from the shipped
files (2026-10-06).

The public beta is meant to be usable by a first-time user, so the console
tells a new analyst what it is, what it must not be used on yet and where to
start: a six-step tour shown once after a first sign-in on a browser and
re-openable from Help, and a Getting started page. The module lives in one
marked block of `app.js` (`guided walkthrough`), its shell in `index.html`
(`#tour-scrim`, `#btn-help`) and its look in `app.css` (`.tour-*`).

Static checks read the assets; the behavioural ones run the real block under
Node against a small DOM stub (skipped where Node is absent, as in
`test_ui_signin_and_cases.py`). A real browser is still owed for focus
order, the ring's look and phone width.

Pure: no database.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from test_ui_copy_no_dashes import _DASH, _FAKE_DASH, js_tokens
from test_ui_copy_no_lazy_plurals import HEDGE

ROOT = Path(__file__).resolve().parents[3]
SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
STATIC = SRC / "http" / "static"

START = "/* \u2500\u2500 guided walkthrough"
END = "/* \u2500\u2500 notifications"

TITLES = [
    "What NocTORnal is",
    "This is a beta",
    "Your first case",
    "The map of the console",
    "Believing things carefully",
    "Where help lives",
]


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _css() -> str:
    return (STATIC / "app.css").read_text(encoding="utf-8")


def _block() -> str:
    js = _js()
    assert js.count(START) == 1, "the walkthrough block marker is missing"
    return js[js.index(START):js.index(END)]


def _fn(name: str, src: str | None = None) -> str:
    """A top-level function: declaration to the first `}` at column 0."""
    js = src if src is not None else _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"no top-level function {name}"
    line = js[m.start():js.index("\n", m.start())]
    if line.rstrip().endswith("}") and line.count("{") == line.count("}"):
        return line + "\n"
    return js[m.start():js.index("\n}", m.start()) + 2] + "\n"


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    default = (Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
               / "nodejs" / "node.exe")
    return str(default) if default.exists() else None


def _run(source: str):
    node = _node()
    if not node:
        pytest.skip("Node is not installed; the browser-side check needs it")
    out = subprocess.run([node, "-"], input=source, capture_output=True,
                         text=True, encoding="utf-8", timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# The shell in index.html
# ---------------------------------------------------------------------------

def test_the_dialog_is_labelled_modal_and_has_a_visible_close():
    html = _html()
    m = re.search(r'<div id="tour-scrim"[^>]*hidden>', html)
    assert m, "the scrim starts hidden"
    sheet = re.search(r'<div id="tour-sheet"[^>]*>', html)
    assert sheet
    tag = sheet.group(0)
    assert 'role="dialog"' in tag
    assert 'aria-modal="true"' in tag
    assert 'aria-labelledby="tour-title"' in tag
    # The label it names is a real heading the dialog can open on.
    assert re.search(r'<h2 id="tour-title"[^>]*tabindex="-1"', html)
    # Close is a button with words, not a bare glyph.
    assert re.search(r'<button id="tour-close"[^>]*>Close</button>', html)
    for button, words in (("tour-skip", "Skip tour"), ("tour-back", "Back"),
                          ("tour-next", "Next"), ("tour-take", "Take the tour")):
        assert re.search(rf'<button id="{button}"[^>]*>\s*{words}\s*</button>',
                         html), button


def test_the_step_counter_and_the_announcement_are_in_the_shell():
    html = _html()
    assert 'id="tour-step"' in html
    live = re.search(r'<p id="tour-live"[^>]*>', html)
    assert live and 'role="status"' in live.group(0) \
        and 'aria-live="polite"' in live.group(0)


def test_help_is_in_the_top_bar_beside_the_inbox_and_account():
    html = _html()
    m = re.search(r'<button id="btn-help"[^>]*>(.*?)</button>', html, re.S)
    assert m and m.group(1).strip() == "Help"
    bar = html[html.index('<header class="appbar">'):html.index("</header>")]
    assert "btn-help" in bar
    assert bar.index("btn-inbox") < bar.index("btn-help") < bar.index("btn-account")


def test_the_shell_has_no_inline_style_or_script():
    html = _html()
    shell = html[html.index('<div id="tour-scrim"'):html.index('<div id="keys-scrim"')]
    assert "style=" not in shell and "<script" not in shell
    assert not re.search(r"\son[a-z]+=", shell)
    help_btn = re.search(r'<button id="btn-help"[^>]*>', html).group(0)
    assert "style=" not in help_btn


# ---------------------------------------------------------------------------
# The block in app.js
# ---------------------------------------------------------------------------

def test_the_block_never_assigns_markup_or_style():
    block = _block()
    forbidden = re.compile(
        r"\.(inner|outer)HTML|insertAdjacentHTML|document\.write|\.srcdoc"
        r"|\.style\b|\.cssText|setAttribute\(\s*['\"]style|\.setProperty\(")
    code = re.sub(r"/\*.*?\*/", "", block, flags=re.S)
    bad = [line.strip() for line in code.splitlines() if forbidden.search(line)]
    assert not bad, bad
    # Text goes in through the console's own helper or a text node.
    assert "el('" in block or "el(" in block
    assert "createTextNode" in block


def test_the_storage_reads_and_writes_are_guarded():
    block = _block()
    uses = re.findall(r"localStorage\.(?:get|set|remove)Item", block)
    assert len(uses) == 2, uses
    for name in ("tourSeen", "rememberTour"):
        body = _fn(name, block)
        assert "try {" in body and "catch" in body, name
    # And nothing else in the block touches storage of any kind.
    assert "sessionStorage" not in block and "indexedDB" not in block


def test_there_are_six_steps_with_the_agreed_titles_and_a_counter():
    block = _block()
    titles = re.findall(r"^    title: '([^']+)',$", block, flags=re.M)
    assert titles == TITLES
    assert "'Step ' + (index + 1) + ' of ' + total" in block
    # The count is the array's own length, never a typed 6.
    assert "TOUR_STEPS.length" in block


def test_the_dialog_is_held_like_the_other_page_dialogs():
    js = _js()
    wire = _fn("wireTour", _block())
    assert "holdDialogKeys('tour-scrim', closeTour)" in wire
    # Focus goes in on open and back to the opener on close.
    open_fn = _fn("openTourDialog", _block())
    assert "document.activeElement" in open_fn and ".focus()" in open_fn
    close_fn = _fn("closeTour", _block())
    assert "TOUR.opener" in close_fn and "btn-help" in close_fn
    # Registered once, from the one place that wires the app.
    assert js.count("  wireTour();\n") == 1 or js.count("  wireTour();\r\n") == 1


def test_the_tour_starts_after_a_sign_in_and_ends_with_the_session():
    js = _js().replace("\r\n", "\n")
    start = js[js.index("async function startApp() {"):]
    start = start[:start.index("\n}\n")]
    assert start.rstrip().endswith("maybeShowWelcomeTour();      // once per "
                                   "browser: see the walkthrough block")
    assert start.index("await showCaseList();") < start.index("maybeShowWelcomeTour")
    # A session that ends under an open tour closes it without marking it
    # read: endSession, the lapse and the sheets that cover the app.
    assert js.count("closeTour(false);") == 3
    # The auto-show is guarded and cannot undo a sign-in.
    auto = _fn("maybeShowWelcomeTour", _block())
    assert "tourAutoShown" in auto and "tourSeen()" in auto and "catch" in auto


def test_the_copy_has_no_dash_fake_dash_or_bracketed_plural():
    block = _block()
    lits, _ = js_tokens(block)
    assert len(lits) > 40, "the lexer lost its place in the block"
    offenders = []
    for _, text in lits:
        if _DASH.search(text) or _FAKE_DASH.search(text) or HEDGE.search(text):
            offenders.append(text)
    assert not offenders, offenders
    # The shell too.
    shell = _html()[_html().index('<div id="tour-scrim"'):
                    _html().index('<div id="keys-scrim"')]
    shell = re.sub(r"<!--.*?-->", "", shell, flags=re.S)
    assert not _DASH.search(shell) and not _FAKE_DASH.search(shell)
    assert not HEDGE.search(shell)


def test_the_steps_use_the_words_the_console_uses():
    """A pane named in the tour is a rail caption, and a control it names
    is on a screen that has it."""
    js, html = _js(), _html()
    names = re.findall(r"^  \['[a-z-]+', '([^']+)', '", js, flags=re.M)
    for pane in ("Graph", "Entities", "Evidence", "Triage", "Report", "Admin"):
        assert pane in names, pane
        assert f'<span class="rail-cap">{pane}</span>' in html, pane
    for caption in ("Add entity", "Add link"):
        assert caption in html
    for label in ("New case", "Create case", "Upload exhibit", "Source entity",
                  "Target entity", "Check readiness", "All cases"):
        assert label in html, label
    assert "Case\u2026" in html
    assert re.search(r'data-subtab="readiness"[^>]*>Readiness', html)
    # The grading words the fifth step names are the forms' own.
    assert "Source reliability" in html and "Info credibility" in html
    assert "Confidence (ICD 203)" in html
    for key, words in (("Persona", "IDENTITY"), ("Assessed person", "PERSON")):
        defs = (ROOT / "packages" / "ontology" / "src" / "noctornal_ontology"
                / "definition.py").read_text(encoding="utf-8")
        assert f'NodeType("{words}", "{key}"' in defs, key


def test_the_manual_and_the_legal_register_the_steps_rest_on_exist():
    """The beta step says what docs/16 says, without citing it (the console
    cites no design document to an analyst: test_search_palette_copy_ui)."""
    assert (ROOT / "release" / "MANUAL.md").is_file()
    legal = (ROOT / "docs" / "16-legal-and-external.md").read_text(encoding="utf-8")
    assert "## Read this before you hold anything" in legal
    assert "synthetic data or on published" in legal
    assert "Legal review is required before any active case load" in legal
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for decision in ("**L1**", "**L2**", "**L3**", "**L4**", "**L5**"):
        assert decision in readme, decision
    block = _block()
    assert "release/MANUAL.md" in block
    assert "The README says which five decisions, L1 to L5" in block
    assert not re.search(r"docs/\d\d|[Ii]nvariant \d|\bPhase \d", block)
    # The word the console uses for what the graph holds.
    assert not re.search(r"\bactors?\b", block, flags=re.I)


def test_the_demo_command_is_the_one_bootstrap_and_the_installer_give():
    block = _block()
    boot = (ROOT / "scripts" / "bootstrap.py").read_text(encoding="utf-8")
    assert '"demo-network"' in boot
    for flag in ("--owner-email", "--code", "--classification"):
        assert f'"{flag}"' in boot, flag
    assert '_TLP_NAMES = ("CLEAR",' in boot
    assert ("'.venv/bin/python scripts/bootstrap.py demo-network "
            "--owner-email '") in block
    assert "' --code OP-LATTICEWORK-26 --classification CLEAR'" in block
    installer = ROOT / "release" / "install.sh"
    if installer.is_file():
        # The installer's closing card gives the code it loaded the demo
        # under (`--code %s`, DEMO_CODE_NAME), which is the code the tour
        # prints and the one `bootstrap.py demo-network` creates when it is
        # given none. OP-SHOWCASE-26 is the README's larger showcase, a
        # different recipe (Beta 1 verification, G6).
        card = installer.read_text(encoding="utf-8")
        assert 'DEMO_CODE_NAME="OP-LATTICEWORK-26"' in card
        assert (".venv/bin/python scripts/bootstrap.py demo-network "
                "--owner-email %s --code %s "
                "--classification CLEAR") in card
        assert 'args.code or "OP-LATTICEWORK-26"' in boot


# ---------------------------------------------------------------------------
# The style in app.css
# ---------------------------------------------------------------------------

def _css_block() -> str:
    css = _css()
    start = css.index("/* -- the walkthrough")
    tail = css.index("@media (prefers-reduced-motion: reduce) {\n  .tour-spot", start)
    return css[start:css.index("\n}\n", tail) + 3]


def test_the_stylesheet_names_the_spotlight_and_respects_reduced_motion():
    css = _css_block()
    for selector in (".tour-sheet", ".tour-spot", ".tour-scrim.tour-spotlit",
                     ".tour-actions", ".tour-map"):
        assert selector in css, selector
    assert re.search(r"@media \(prefers-reduced-motion: reduce\)\s*\{\s*"
                     r"\.tour-spot\s*\{\s*transition: none;", css)
    # A narrow screen stacks the pane list, and the actions wrap.
    assert "@media (max-width: 700px)" in css
    assert "flex-wrap: wrap" in css


def test_the_stylesheet_block_uses_tokens_and_no_colour_literals():
    css = re.sub(r"/\*.*?\*/", "", _css_block(), flags=re.S)
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\(", css)
    used = set(re.findall(r"var\((--[a-z0-9-]+)\)", css))
    theme = (STATIC / "theme.css").read_text(encoding="utf-8")
    app = _css()
    for token in used:
        assert re.search(rf"^\s*{re.escape(token)}\s*:", theme + app, re.M), token


# ---------------------------------------------------------------------------
# The block, run
# ---------------------------------------------------------------------------

def _fns(*names: str) -> str:
    js = _js()
    return "\n".join(_fn(n, js) for n in names)


_STUB = r"""
'use strict';
const focusLog = [];
const all = [];
const doc = { activeElement: null };
class Txt {
  constructor(t) { this.nodeType = 3; this.textContent = String(t); this.parent = null; }
}
class N {
  constructor(tag) {
    this.tag = tag; this.id = ''; this.children = []; this.parent = null;
    this.hidden = false; this.className = ''; this._text = '';
    this.classes = new Set(); this.scrollTop = 0; this.visible = true;
    this.listeners = {};
    const self = this;
    this.classList = {
      add(c) { self.classes.add(c); },
      remove(c) { self.classes.delete(c); },
      contains(c) { return self.has(c); },
    };
    all.push(this);
  }
  has(c) { return this.classes.has(c) || this.className.split(' ').includes(c); }
  get textContent() {
    return this._text + this.children.map((c) => c.textContent).join('');
  }
  set textContent(v) { this._text = String(v); this.children = []; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  get firstChild() { return this.children[0] || null; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); c.parent = null; return c; }
  focus() { doc.activeElement = this; focusLog.push(this.id || this.tag); }
  closest(sel) {
    for (let n = this; n; n = n.parent) if (sel === '[hidden]' && n.hidden) return n;
    return null;
  }
  getClientRects() { return this.visible ? [1] : []; }
  scrollIntoView() { this.scrolled = true; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  walk(tag, out = []) {
    for (const c of this.children) {
      if (c.tag === tag) out.push(c);
      if (c.walk) c.walk(tag, out);
    }
    return out;
  }
}
const ids = {};
const bySelector = {};
const document = {
  createElement: (tag) => new N(tag),
  createTextNode: (t) => new Txt(t),
  querySelector: (sel) => bySelector[sel] || null,
  querySelectorAll: (sel) => (sel === '.tour-spot' ? all.filter((n) => n.has('tour-spot')) : []),
  contains: (n) => !n.detached,
  get activeElement() { return doc.activeElement; },
  body: new N('body'),
};
function $(id) {
  if (!ids[id]) { ids[id] = new N('x'); ids[id].id = id; }
  return ids[id];
}
const state = { cases: [], caseId: null };
const SESSION = { email: '' };
let storage = { items: {}, getItem(k) { return k in this.items ? this.items[k] : null; },
                setItem(k, v) { this.items[k] = String(v); } };
const localStorage = {
  getItem: (k) => storage.getItem(k),
  setItem: (k, v) => storage.setItem(k, v),
};
const held = [];
function holdDialogKeys(id, close) { held.push([id, close]); }
$('tour-scrim').hidden = true;
$('btn-help').tag = 'button';
"""


def _harness(scenario: str) -> str:
    return "\n".join([
        _STUB,
        _fns("el", "clear", "show"),
        _block(),
        scenario,
    ])


@pytest.fixture(scope="module")
def walk():
    return _run(_harness(r"""
const helpBtn = $('btn-help');
helpBtn.focus();
openTourDialog('tour');
const opened = { hidden: $('tour-scrim').hidden, focus: doc.activeElement.id };
const steps = [];
for (let i = 0; i < TOUR_STEPS.length; i++) {
  steps.push({
    counter: $('tour-step').textContent,
    counterShown: !$('tour-step').hidden,
    title: $('tour-title').textContent,
    text: $('tour-body').textContent,
    back: !$('tour-back').hidden,
    skip: !$('tour-skip').hidden,
    next: $('tour-next').textContent,
    live: $('tour-live').textContent,
  });
  if (i < TOUR_STEPS.length - 1) tourMove(1);
}
tourMove(1);   // Done on the last step
const closed = { hidden: $('tour-scrim').hidden, seen: storage.items,
                 focus: doc.activeElement.id };
console.log(JSON.stringify({ opened, steps, closed }));
"""))


def test_the_tour_walks_six_steps_with_a_counter(walk):
    assert [s["title"] for s in walk["steps"]] == TITLES
    assert [s["counter"] for s in walk["steps"]] == [
        f"Step {i} of 6" for i in range(1, 7)]
    assert all(s["counterShown"] for s in walk["steps"])
    assert walk["steps"][1]["counter"] == "Step 2 of 6"
    # A screen reader is told the step and its title.
    assert walk["steps"][1]["live"] == "Step 2 of 6. This is a beta"


def test_the_buttons_follow_the_step(walk):
    steps = walk["steps"]
    assert steps[0]["back"] is False and steps[0]["skip"] is True
    assert all(s["back"] for s in steps[1:])
    assert steps[-1]["next"] == "Done" and steps[-1]["skip"] is False
    assert all(s["next"] == "Next" for s in steps[:-1])


def test_it_opens_on_the_heading_and_closing_marks_it_seen_and_returns_focus(walk):
    assert walk["opened"] == {"hidden": False, "focus": "tour-title"}
    assert walk["closed"]["hidden"] is True
    assert walk["closed"]["seen"] == {"noctornal.tour.seen": "1"}
    assert walk["closed"]["focus"] == "btn-help"


def test_every_step_reads_without_banned_characters(walk):
    for step in walk["steps"]:
        assert not _DASH.search(step["text"]) and not _FAKE_DASH.search(step["text"])
        assert not HEDGE.search(step["text"])
        assert step["text"].strip()


def test_the_beta_step_says_what_the_legal_register_says(walk):
    text = walk["steps"][1]["text"]
    assert "synthetic data" in text and "no personal data" in text
    assert "legal review" in text and "L1 to L5" in text


def test_the_fifth_step_names_the_grades_and_the_two_rules(walk):
    text = walk["steps"][4]["text"]
    for phrase in ("A to F", "1 to 6", "confidence", "Machines only propose",
                   "A handle is not a person", "Nothing is a fact"):
        assert phrase in text, phrase


def test_the_map_names_the_six_panes_in_order(walk):
    text = walk["steps"][3]["text"]
    order = [text.index(p) for p in ("Graph", "Entities", "Evidence", "Triage",
                                     "Report", "Admin")]
    assert order == sorted(order)


def test_the_last_step_points_at_the_manual_and_readiness(walk):
    text = walk["steps"][5]["text"]
    assert "release/MANUAL.md" in text
    assert "Admin, then Readiness" in text


def test_the_first_case_step_depends_on_whether_there_are_cases():
    out = _run(_harness(r"""
const idx = TOUR_STEPS.findIndex((s) => s.title === 'Your first case');
function stepText() {
  TOUR.view = 'tour'; TOUR.index = idx; paintTour();
  return { text: $('tour-body').textContent,
           code: $('tour-body').walk('pre').map((p) => p.textContent) };
}
const empty = stepText();
SESSION.email = 'ana@example.org';
const named = stepText();
SESSION.email = 'a b; rm -rf /@x';
const unsafe = stepText();
state.cases = [{ id: 'c1' }];
const some = stepText();
console.log(JSON.stringify({ empty, named, unsafe, some }));
"""))
    base = (".venv/bin/python scripts/bootstrap.py demo-network "
            "--owner-email {} --code OP-LATTICEWORK-26 --classification CLEAR")
    assert out["empty"]["code"] == [base.format("YOU")]
    assert out["named"]["code"] == [base.format("ana@example.org")]
    assert out["unsafe"]["code"] == [base.format("YOU")]
    assert "New case" in out["empty"]["text"] and "Create case" in out["empty"]["text"]
    # With cases, the Case button and the list are what is pointed at.
    assert out["some"]["code"] == []
    assert "Case\u2026" in out["some"]["text"] and "All cases" in out["some"]["text"]


def test_the_spotlight_follows_the_step_and_never_traps_a_missing_target():
    out = _run(_harness(r"""
const rail = new N('nav'); bySelector['.rail'] = rail;
const help = $('btn-help'); bySelector['#btn-help'] = help;
const form = new N('form'); bySelector['#case-form'] = form;
function at(i) { TOUR.view = 'tour'; TOUR.index = i; paintTour(); }
const r = {};
openTourDialog('tour');
at(0); r.first = [rail.has('tour-spot'), $('tour-scrim').has('tour-spotlit')];
at(2); r.caseList = [form.has('tour-spot'), rail.has('tour-spot')];
at(3); r.map = [rail.has('tour-spot'), form.has('tour-spot'),
                $('tour-scrim').has('tour-spotlit'), rail.scrolled === true];
at(4); r.after = [rail.has('tour-spot'), $('tour-scrim').has('tour-spotlit')];
at(5); r.last = [help.has('tour-spot')];      // #tab-admin and #btn-admin are not on screen
rail.visible = false;
at(3); r.hiddenRail = [rail.has('tour-spot'), $('tour-scrim').has('tour-spotlit'),
                       $('tour-title').textContent];
rail.visible = true; at(3);
closeTour();
r.closed = [rail.has('tour-spot'), help.has('tour-spot'),
            $('tour-scrim').has('tour-spotlit')];
console.log(JSON.stringify(r));
"""))
    assert out["first"] == [False, False]
    assert out["caseList"] == [True, False]
    assert out["map"] == [True, False, True, True]
    assert out["after"] == [False, False]
    assert out["last"] == [True]
    assert out["hiddenRail"] == [False, False, "The map of the console"]
    assert out["closed"] == [False, False, False]


def test_storage_that_throws_neither_breaks_the_tour_nor_repeats_it():
    out = _run(_harness(r"""
storage = { getItem() { throw new Error('blocked'); },
            setItem() { throw new Error('blocked'); } };
const r = {};
r.seen = tourSeen();
maybeShowWelcomeTour();
r.opened = !$('tour-scrim').hidden;
closeTour();                  // setItem throws inside: must not escape
r.closed = $('tour-scrim').hidden;
maybeShowWelcomeTour();       // blocked storage: still once per page load
r.again = !$('tour-scrim').hidden;
console.log(JSON.stringify(r));
"""))
    assert out == {"seen": False, "opened": True, "closed": True, "again": False}


def test_a_seen_tour_is_not_shown_again():
    out = _run(_harness(r"""
const r = {};
maybeShowWelcomeTour();
r.first = !$('tour-scrim').hidden;
closeTour();
tourAutoShown = false;        // a new page load in the same browser
r.seenAfter = tourSeen();
maybeShowWelcomeTour();
r.second = !$('tour-scrim').hidden;
console.log(JSON.stringify(r));
"""))
    assert out == {"first": True, "seenAfter": True, "second": False}


def test_a_close_made_by_the_session_ending_neither_remembers_nor_moves_focus():
    out = _run(_harness(r"""
$('btn-help').focus();
openTourDialog('tour');
const before = focusLog.length;
closeTour(false);
console.log(JSON.stringify({ hidden: $('tour-scrim').hidden,
  stored: storage.items, moved: focusLog.length - before }));
"""))
    assert out == {"hidden": True, "stored": {}, "moved": 0}


def test_help_opens_getting_started_with_five_things_and_the_way_into_the_tour():
    out = _run(_harness(r"""
openTourDialog('help');
const r = {};
r.title = $('tour-title').textContent;
r.counterShown = !$('tour-step').hidden;
r.items = $('tour-body').walk('li').map((li) => li.textContent);
r.take = !$('tour-take').hidden;
r.next = !$('tour-next').hidden;
r.skip = !$('tour-skip').hidden;
r.back = !$('tour-back').hidden;
console.log(JSON.stringify(r));
"""))
    assert out["title"] == "Getting started"
    assert out["counterShown"] is False
    assert len(out["items"]) == 5
    assert out["take"] is True
    assert not (out["next"] or out["skip"] or out["back"])
    assert out["items"][0].startswith("Open a case.")
    assert "Readiness" in out["items"][4]


def test_take_the_tour_from_help_starts_at_step_one():
    out = _run(_harness(r"""
const click = {};
$('tour-take').addEventListener = (t, f) => { click.take = f; };
$('tour-next').addEventListener = (t, f) => { click.next = f; };
$('tour-back').addEventListener = (t, f) => { click.back = f; };
$('tour-skip').addEventListener = (t, f) => { click.skip = f; };
$('tour-close').addEventListener = (t, f) => { click.close = f; };
$('btn-help').addEventListener = (t, f) => { click.help = f; };
wireTour();
click.help();
const r = { helpTitle: $('tour-title').textContent, dialogs: held.map((h) => h[0]) };
click.take();
r.tourTitle = $('tour-title').textContent;
r.counter = $('tour-step').textContent;
r.focus = doc.activeElement.id;
click.next(); click.next();
r.third = $('tour-step').textContent;
click.back();
r.back = $('tour-step').textContent;
click.skip();
r.hidden = $('tour-scrim').hidden;
console.log(JSON.stringify(r));
"""))
    assert out["helpTitle"] == "Getting started"
    assert out["dialogs"] == ["tour-scrim"]
    assert out["tourTitle"] == "What NocTORnal is"
    assert out["counter"] == "Step 1 of 6"
    assert out["focus"] == "tour-next"
    assert out["third"] == "Step 3 of 6" and out["back"] == "Step 2 of 6"
    assert out["hidden"] is True


def test_a_button_that_goes_away_does_not_strand_the_focus():
    out = _run(_harness(r"""
openTourDialog('tour');
tourMove(1);
$('tour-back').focus();       // the keyboard user is on Back, at step 2
tourMove(-1);                 // Back is hidden at step 1
console.log(JSON.stringify({ focus: doc.activeElement.id,
                             counter: $('tour-step').textContent }));
"""))
    assert out == {"focus": "tour-next", "counter": "Step 1 of 6"}
