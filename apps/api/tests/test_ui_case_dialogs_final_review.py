"""The case dialogs, the tab title, the tag picker and Share's end time,
held from the shipped files (final review of the Alpha 6 candidate,
2026-09-24).

- c22: the Case record, Status and Share dialogs said `aria-modal` and held
  only Tab and Escape, so Ctrl+K, ? and Alt+digit acted on the page behind
  them and one Escape closed the palette and the dialog together, taking a
  typed correction with it;
- u18: the tab title carried the case code and its TLP marking into the
  browser's history, which Log out cannot clear;
- u24: the tag picker's prompt had no value, so Tag posted the prompt's
  text as a tag id;
- u26: Share's "Access ends" was typed and read in the browser's zone, the
  one time in the console that was not UTC.

Pure, like test_ui_invariants.py beside it: static assets, and the real
functions run under Node against stubs where the claim is about behaviour
(skipped where Node is absent).
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


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function: declaration to the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    line = js[m.start():js.index("\n", m.start())]
    if line.rstrip().endswith("}") and line.count("{") == line.count("}"):
        return line + "\n"
    return js[m.start():js.index("\n}", m.start()) + 2] + "\n"


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    default = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "node.exe"
    return str(default) if default.exists() else None


def _run(source: str, tz: str | None = None):
    node = _node()
    if not node:
        pytest.skip("Node is not installed; the browser-side check needs it")
    env = dict(os.environ)
    if tz:
        env["TZ"] = tz
    out = subprocess.run([node, "-"], input=source, capture_output=True,
                         text=True, encoding="utf-8", timeout=60, env=env)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# c22: the page dialogs are modal in fact
# ---------------------------------------------------------------------------

#: A DOM just deep enough to dispatch a keydown the way a browser does:
#: capture from the window down to the target, then bubble back up, with
#: stopPropagation honoured between nodes.
_EVENTS = r"""
function node(id, parent) {
  return { id, parent, hidden: false, listeners: [], tagName: 'DIV',
    addEventListener(type, fn, capture) {
      this.listeners.push({ type, fn, capture: !!capture }); },
    contains(n) { for (let x = n; x; x = x.parent) if (x === this) return true;
                  return false; },
    focus() { document.activeElement = this; },
    closest() { return null; }, getClientRects() { return [1]; } };
}
const window = node('window', null);
const document = node('document', window);
const body = node('body', document);
document.activeElement = body;
const els = {};
function add(id, parent, tag) { const n = node(id, parent); n.tagName = tag || 'DIV';
  els[id] = n; return n; }
function $(id) { return els[id] || null; }
function dispatch(target, key, mods) {
  const e = Object.assign({ key, target, ctrlKey: false, metaKey: false,
    altKey: false, shiftKey: false, defaultPrevented: false, stopped: false,
    preventDefault() { this.defaultPrevented = true; },
    stopPropagation() { this.stopped = true; } }, mods || {});
  const path = [];
  for (let x = target; x; x = x.parent) path.push(x);
  const run = (n, capture) => {
    for (const l of n.listeners) {
      if (l.type !== 'keydown' || l.capture !== capture) continue;
      e.currentTarget = n; l.fn(e);
    }
  };
  for (const n of path.slice().reverse()) { if (e.stopped) break; run(n, true); }
  for (const n of path) { if (e.stopped) break; run(n, false); }
  return e;
}
"""


def test_the_case_status_and_share_dialogs_keep_every_key_from_the_page():
    wire = _fn("wireCaseActions")
    for scrim in ("case-scrim", "status-scrim", "share-scrim"):
        assert f"holdDialogKeys('{scrim}'," in wire, scrim
    # No dialog listens on the document any more: that is where the page's
    # own shortcuts are, and both ran on one key.
    assert "document.addEventListener('keydown'" not in wire
    assert "document.addEventListener" not in _fn("holdDialogKeys")

    got = _run(_EVENTS + r"""
let sheet = null;
function topSessionSheet() { return sheet; }
const scrim = add('case-scrim', body);
const summary = add('case-edit-summary', scrim, 'TEXTAREA');
const save = add('case-edit-save', scrim, 'BUTTON');
const close = add('case-close', scrim, 'BUTTON');
scrim.querySelectorAll = () => [summary, save, close];
const page = [];
// The page's shortcuts and the palette's Escape, as initPalette has them.
document.addEventListener('keydown', (e) => page.push(e.key));
let closed = 0;
""" + "const PAGE_DIALOGS = new Map();\n" + _fn("openPageDialog")
        + _fn("dialogFocusables") + _fn("cycleDialogFocus") + _fn("isPaletteKey")
        + _fn("dialogKey") + _fn("onPageDialogKey") + _fn("holdDialogKeys") + r"""
holdDialogKeys('case-scrim', () => { closed += 1; scrim.hidden = true; });
const out = {};
const k = dispatch(summary, 'k', { ctrlKey: true });
out.ctrlK = { page: page.length, prevented: k.defaultPrevented };
dispatch(close, '3', { altKey: true });
const q = dispatch(summary, '?');
out.question = { page: page.length, prevented: q.defaultPrevented };
dispatch(summary, 'Escape');
out.escape = { page: page.length, closed };
// Focus dropped to <body> by a button disabled in flight.
scrim.hidden = false;
dispatch(body, 'k', { ctrlKey: true });
dispatch(body, '3', { altKey: true });
out.body = { page: page.length };
dispatch(body, 'Escape');
out.bodyEscape = { page: page.length, closed };
// Tab from the last control wraps to the first, and from <body> goes in.
scrim.hidden = false;
close.focus();
dispatch(close, 'Tab');
out.wrap = document.activeElement.id;
document.activeElement = body;
dispatch(body, 'Tab');
out.fromBody = document.activeElement.id;
// A session sheet on top has the keyboard: this handler stands aside.
sheet = {};
dispatch(body, 'Escape');
out.underSheet = { closed };
sheet = null;
page.length = 0;              // `onSheetKey` would have taken that Escape
// Closed, the page has its keys back.
scrim.hidden = true;
dispatch(body, 'k', { ctrlKey: true });
out.after = { page: page.slice() };
console.log(JSON.stringify(out));
""")
    assert got["ctrlK"] == {"page": 0, "prevented": True}, got
    # ? still types into the field it was pressed in; only the page misses it.
    assert got["question"] == {"page": 0, "prevented": False}, got
    assert got["escape"] == {"page": 0, "closed": 1}, (
        "one Escape reached the page as well as the dialog")
    assert got["body"] == {"page": 0}, "a key on <body> reached the page's shortcuts"
    assert got["bodyEscape"] == {"page": 0, "closed": 2}
    assert got["wrap"] == "case-edit-summary" and got["fromBody"] == "case-edit-summary"
    assert got["underSheet"] == {"closed": 2}
    assert got["after"] == {"page": ["k"]}


# ---------------------------------------------------------------------------
# u18: the tab title names no case and no marking
# ---------------------------------------------------------------------------

def test_the_tab_title_carries_neither_the_case_code_nor_its_marking():
    title = _run(_fn("caseTitle") + r"""
console.log(JSON.stringify(caseTitle({ code: 'OP-HALCYON-25', classification: 'RED' })));
""")
    assert "OP-HALCYON-25" not in title and "RED" not in title and "TLP" not in title
    assert title == "Case · NocTORnal"
    js = _js()
    for line in (ln for ln in js.splitlines() if "document.title =" in ln):
        assert "rec." not in line and "code" not in line, line.strip()


# ---------------------------------------------------------------------------
# u24: the tag picker's prompt is never sent as a tag
# ---------------------------------------------------------------------------

def test_tag_with_the_prompt_still_chosen_sends_nothing():
    got = _run(r"""
function el(tag, cls, text) {
  const n = { tag, className: cls, textContent: text == null ? '' : String(text),
    children: [], attrs: {}, disabled: false, selected: false, listeners: {},
    appendChild(c) { this.children.push(c); return c; },
    setAttribute(k, v) { this.attrs[k] = v; },
    addEventListener(t, fn) { this.listeners[t] = fn; },
    focus() { calls.push('focus ' + this.tag); } };
  if (tag === 'option') {
    // A browser's rule: an option with no value attribute submits its text.
    Object.defineProperty(n, 'value', { get() { return this._v === undefined
      ? this.textContent : this._v; }, set(v) { this._v = v; } });
  }
  if (tag === 'select') {
    Object.defineProperty(n, 'value', { get() {
      const o = this.children.find((c) => c.selected) || this.children[0];
      return o ? o.value : ''; } });
  }
  return n;
}
const calls = [];
const state = { caseTags: [{ id: 't1', namespace: 'role', name: 'broker', scope: 'case' }] };
function api(path) { calls.push('api ' + path); return Promise.resolve({}); }
function cpath(p) { return p; }
function renderInspector() {}
function fail(err) { calls.push('fail ' + err); }
function banner() {}
const box = el('div');
""" + _fn("renderTags") + r"""
renderTags(box, [], { id: 'n1' });
const row = box.children.find((c) => c.className === 'insp-linker');
const go = row.children.find((c) => c.tag === 'button');
go.listeners.click();
console.log(JSON.stringify(calls));
""")
    assert not any(c.startswith("api ") for c in got), got
    assert got == ["focus select"], got


# ---------------------------------------------------------------------------
# u26: Share's end time is UTC, as every other time in the console
# ---------------------------------------------------------------------------

def test_share_access_ends_is_typed_and_sent_as_utc():
    html = _html()
    field = html[html.index("share-expires") - 200:html.index("share-expires")]
    assert "Access ends (optional, UTC)" in field
    assert "local time" not in field
    got = _run(r"""
const vals = { 'share-email': 'b@example.test', 'share-role': 'ANALYST',
               'share-expires': '2026-09-30T17:00' };
const els = {};
function $(id) { if (!els[id]) els[id] = { id, get value() { return vals[id] || ''; },
  set value(v) { vals[id] = v; }, hidden: false, disabled: false, focus() {} };
  return els[id]; }
function setMsg() {}
const state = { caseId: 'c1', caseRec: { code: 'OP-X' } };
let sent = null;
async function api(_p, opts) { sent = opts.json; return {}; }
function caseToken() { return 1; }
function caseChanged() { return false; }
function shareOutcome() { return ''; }
function shareRefusal() { return ''; }
function loadShareRoster() {}
""" + _fn("submitShare") + r"""
submitShare({ preventDefault() {} }).then(() =>
  console.log(JSON.stringify({ sent, offset: new Date(2026, 8, 30).getTimezoneOffset() })));
""", tz="America/Halifax")
    assert got["offset"] != 0, "the check needs a zone that is not UTC"
    assert got["sent"]["expires_at"] == "2026-09-30T17:00:00.000Z", got
