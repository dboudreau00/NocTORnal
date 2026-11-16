"""Stop, Resume and Edit on a watch row of the Collected tab (docs/17: stopping or editing a watch).

The rows sit in the Feeds pane's Collected tab, under the hits the watches produce. Pure: no database.
The functions run under Node over the same stub DOM the Sources tests use, and are judged by what they
draw and what they send. The server half is test_collection_watch_change_pg.py, and the closed-case
table (test_closed_case_read_only.py) holds that Stop is the one of the three a read-only case allows.

What is held here:

- the controls are drawn only for a caller who holds `watch.manage` (the listing's `can_create`): Stop
  and Edit on an active watch, Resume and Edit on a stopped one;
- Stop carries no `case-write` class, so it stays live on a read-only case, and Resume and Edit carry
  it, so the case turns them off as it does every other write;
- the Edit form is filled from the watch's own name and lists and never from what the row shows, which
  rewrites a deceptive character as `<U+202E>`: saving that rewrite would store it as a term;
- an edit sends only the fields that differ, minutes become seconds, and a form with nothing changed
  sends nothing;
- a refusal is said on the row or in the form, and a fault is not swallowed.
"""
from __future__ import annotations

import json
import re

import pytest

from test_collection_ui_foundation import _const, _fn, _run
from test_ui_copy_no_dashes import NODE, _html, _js, js_tokens
from test_watch_create_ui import PRELUDE, WATCH

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

#: Every function and constant the row and its form use, loaded from app.js itself.
FUNCTIONS = ["watchRow", "watchActions", "watchEdit", "editWatchForm", "watchWindowText",
             "infoTip"]
CONSTS = ["WATCH_KIND_WORDS", "WATCH_CHAT_KIND", "WATCH_PRIORITIES", "WATCH_MAX_MINUTES",
          "COL_WATCHES_NOT_LOADED", "WATCH"]

#: The rule the stubs lack: a deceptive character is rewritten as the console writes it.
RENDER_RULE = r"""
visibleText = (s) => (s === null || s === undefined ? '' : String(s)).replace(/\u202e/g, '<U+202E>');
"""


def run(body: str, tmp_path, *, extra=(), watch=None):
    """Node over the stubs, with the row functions and a `W` for the watch under test."""
    head = PRELUDE + "\nconst W = " + json.dumps(WATCH if watch is None else watch) + ";\n"
    head += "globalThis.loadWatches = () => calls.push({ reload: 'watches' });\n"
    return _run([*FUNCTIONS, *extra], head + body, tmp_path, consts=CONSTS)


# ---------------------------------------------------------------------------
# The controls
# ---------------------------------------------------------------------------

@needs_node
def test_a_row_offers_stop_edit_and_resume_only_to_a_manager(tmp_path):
    got = run("""
const names = (n) => buttons(n);
const stoppedTip = all(watchRow({ ...W, is_active: false }, true),
  (x) => x.dataset && x.dataset.tip).map((x) => x.dataset.tip);
console.log(JSON.stringify({
  noSecondArgument: names(watchRow(W)),
  reader: names(watchRow(W, false)),
  readerStopped: names(watchRow({ ...W, is_active: false }, false)),
  active: names(watchRow(W, true)),
  stopped: names(watchRow({ ...W, is_active: false }, true)),
  stoppedTip,
  readerActions: all(watchRow(W, false), (x) => x.className === 'row-actions').length,
  managerActions: all(watchRow(W, true), (x) => x.className === 'row-actions').length,
}));
""", tmp_path)
    assert got["noSecondArgument"] == [] and got["reader"] == [], (
        "a row drawn with no second argument, or for a reader, carries no control")
    assert got["readerStopped"] == ["i"], "a reader of a stopped watch still has the note on it"
    assert got["active"] == ["Stop", "Edit…"]
    assert got["stopped"] == ["i", "Resume", "Edit…"], "the i is the note on the stopped chip"
    assert got["stoppedTip"] == [
        "Stopped: it matches nothing and its patterns cost nothing. Resume it to task it again."]
    assert (got["readerActions"], got["managerActions"]) == (0, 1)


@needs_node
def test_stop_has_no_case_write_class_and_edit_and_resume_have_it(tmp_path):
    got = run("""
const classes = (n) => Object.fromEntries(all(n, (x) => x.tag === 'button' && x.textContent !== 'i')
  .map((x) => [x.textContent, x.className]));
console.log(JSON.stringify({
  active: classes(watchRow(W, true)),
  stopped: classes(watchRow({ ...W, is_active: false }, true)),
}));
""", tmp_path)
    for row in (got["active"], got["stopped"]):
        assert "case-write" in row["Edit…"]
    assert "case-write" not in got["active"]["Stop"], (
        "Stop stays live on a read-only case: it is the only way a closed case's watch is quietened")
    assert "case-write" in got["stopped"]["Resume"]


def test_a_read_only_case_turns_off_what_carries_case_write_and_the_form_with_it():
    js = _js()
    block = js[js.index("const CASE_CONTENT_RENDERED = ["):]
    assert "'.case-write'" in block[:block.index("].join")], (
        "the class is how a drawn write is turned off with its case")
    edit = _fn("editWatchForm")
    assert "write: ' case-write'" in edit, "a form still open when its case closes is turned off"


# ---------------------------------------------------------------------------
# Stop and Resume
# ---------------------------------------------------------------------------

@needs_node
def test_stop_and_resume_post_to_their_routes_and_read_the_list_again(tmp_path):
    got = run("""
globalThis.apiAnswer = () => ({ changed: true });
const active = watchRow(W, true);
const stop = all(active, (x) => x.textContent === 'Stop')[0];
await stop.listeners.click();
const first = calls.splice(0);
const stopped = watchRow({ ...W, is_active: false, id: 'W 2/x' }, true);
const resume = all(stopped, (x) => x.textContent === 'Resume')[0];
await resume.listeners.click();
console.log(JSON.stringify({ first, second: calls.splice(0),
  aria: [stop.attrs['aria-label'], resume.attrs['aria-label']] }));
""", tmp_path)
    assert got["first"] == [
        {"path": "/cases/C1/collection/watches/W1/stop", "opts": {"method": "POST"}},
        {"reload": "watches"}]
    assert got["second"] == [
        {"path": "/cases/C1/collection/watches/W%202%2Fx/resume", "opts": {"method": "POST"}},
        {"reload": "watches"}], "the id is encoded into the path"
    assert got["aria"] == ["Stop nightjar", "Resume nightjar"]


@needs_node
def test_a_refusal_is_said_on_the_row_and_a_server_fault_is_not_swallowed(tmp_path):
    got = run("""
const row = watchRow(W, true);
const stop = all(row, (x) => x.textContent === 'Stop')[0];
const notes = () => all(row, (x) => x.className === 'form-error').map((x) => x.textContent);
globalThis.apiAnswer = () => { throw new ApiError(404, 'no such watch on this case'); };
await stop.listeners.click();
const first = { notes: notes(), busy: stop.disabled };
await stop.listeners.click();
const again = notes();
const out = { first, again };
globalThis.apiAnswer = () => { throw new Error('boom'); };
try { await stop.listeners.click(); out.fault = 'swallowed'; } catch (e) { out.fault = e.message; }
out.busy = stop.disabled;
out.reloads = calls.filter((c) => c.reload).length;
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["first"] == {"notes": ["Not stopped: no such watch on this case"], "busy": False}
    assert got["again"] == ["Not stopped: no such watch on this case"], (
        "a second refusal replaces the first and does not pile up")
    assert got["fault"] == "boom" and got["busy"] is False and got["reloads"] == 0


# ---------------------------------------------------------------------------
# The Edit form
# ---------------------------------------------------------------------------

@needs_node
def test_edit_opens_a_form_with_the_watchs_own_values_and_says_what_cannot_change(tmp_path):
    got = run("""
const card = watchRow(W, true);
const edit = all(card, (x) => x.textContent === 'Edit…')[0];
edit.listeners.click();
const spec = card.lastSpec;
console.log(JSON.stringify({ kind: spec.kind, write: spec.write, submit: spec.submit,
  help: spec.help,
  fields: spec.fields.map((f) => [f.label, f.value, !!f.multiline, !!f.options, f.rows || null]),
  options: spec.fields[4].options }));
""", tmp_path)
    assert got["kind"] == "edit-watch" and got["write"] == " case-write" and got["submit"] == "Save"
    assert got["help"].startswith("The source and what it looks at cannot be changed. To aim a "
                                  "watch somewhere else, stop it and add a new one.")
    assert got["fields"] == [
        ["Name", "nightjar", False, False, None],
        ["Keywords, one per line", "a\nb", True, False, 4],
        ["Selectors, one per line", "s@x.test", True, False, 4],
        ["Patterns, one per line", "p+", True, False, 4],
        ["Priority", "2", False, True, None],
        ["Thin repeats on a thread (minutes)", "30", False, False, None]]
    assert got["options"] == [["1", "1 (most urgent)"], ["2", "2"], ["3", "3"], ["4", "4"],
                              ["5", "5 (least urgent)"]]


@needs_node
def test_edit_prefills_the_raw_terms_not_the_rendered_ones(tmp_path):
    """The row draws a term through `visibleText`, which writes a deceptive character as
    `<U+202E>`. The form is filled from the watch's own text, so saving it does not store that
    rewrite, and a term nobody touched is not sent at all."""
    got = run(RENDER_RULE + """
const w = { ...W, name: 'night\\u202ejar', keywords: ['a\\u202eb', 'plain'] };
const card = watchRow(w, true);
const rendered = text(card);
all(card, (x) => x.textContent === 'Edit…')[0].listeners.click();
const spec = card.lastSpec;
const prefill = spec.fields.map((f) => f.value);
const out = { rendered: rendered.includes('<U+202E>'), name: prefill[0], keywords: prefill[1],
  untouched: spec.check(prefill) };
const values = prefill.slice();
values[1] = prefill[1] + '\\nthird';
out.problem = spec.check(values);
await spec.submitFn(values);
out.sent = calls.filter((c) => c.opts).map((c) => c.opts.json);
const renamed = prefill.slice();
renamed[4] = '5';
await spec.submitFn(renamed);
out.priorityOnly = calls.filter((c) => c.opts).map((c) => c.opts.json).slice(1);
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["rendered"] is True, "the row shows the rewrite"
    assert got["name"] == "night\u202ejar", "the form holds the name as stored"
    assert "\u202e" in got["keywords"] and "<U+202E>" not in got["keywords"]
    assert got["untouched"] == "Nothing changed."
    assert got["problem"] is None
    assert got["sent"] == [{"keywords": ["a\u202eb", "plain", "third"]}], (
        "a term that was not touched goes back exactly as it was stored")
    assert got["priorityOnly"] == [{"priority": 5}], "an untouched list is not sent"


@needs_node
def test_an_edit_sends_only_the_fields_that_changed_and_minutes_become_seconds(tmp_path):
    got = run("""
const card = watchRow(W, true);
all(card, (x) => x.textContent === 'Edit…')[0].listeners.click();
const spec = card.lastSpec;
const base = spec.fields.map((f) => f.value);
const out = [];
async function attempt(over) {
  const values = base.slice();
  for (const k of Object.keys(over)) values[Number(k)] = over[k];
  const problem = spec.check(values);
  calls.length = 0;
  if (!problem) await spec.submitFn(values);
  out.push({ problem, calls: calls.slice() });
}
await attempt({ 0: '  renamed  ', 4: '1', 5: '5' });
await attempt({ 2: '' });
await attempt({ 1: ' a \\n\\n b \\n c ', 3: '  ' });
await attempt({ 5: '0' });
await attempt({ 5: ' 30 ' });
console.log(JSON.stringify(out));
""", tmp_path)
    first, cleared, relisted, instant, same = got
    assert first["calls"][0] == {
        "path": "/cases/C1/collection/watches/W1",
        "opts": {"method": "PATCH", "json": {"name": "renamed", "priority": 1,
                                             "suppress_window_s": 300}}}
    assert first["calls"][1] == {"reload": "watches"}
    assert cleared["calls"][0]["opts"]["json"] == {"selectors": []}, "an empty box clears the list"
    assert relisted["calls"][0]["opts"]["json"] == {"keywords": ["a", "b", "c"], "regexes": []}, (
        "lines are trimmed and blank ones dropped")
    assert instant["calls"][0]["opts"]["json"] == {"suppress_window_s": 0}
    assert same["problem"] == "Nothing changed." and same["calls"] == []


@needs_node
def test_a_window_that_is_not_whole_minutes_is_left_alone_until_it_is_changed(tmp_path):
    got = run("""
const w = { ...W, suppress_window_s: 90 };
const card = watchRow(w, true);
all(card, (x) => x.textContent === 'Edit…')[0].listeners.click();
const spec = card.lastSpec;
const base = spec.fields.map((f) => f.value);
const priority = base.slice(); priority[4] = '4';
const touched = base.slice(); touched[5] = '2';
const bad = base.slice(); bad[5] = '1.5x';
console.log(JSON.stringify({ shown: base[5], untouched: spec.check(base),
  priority: spec.check(priority), touched: spec.check(touched), bad: spec.check(bad) }));
""", tmp_path)
    assert got["shown"] == "1.5", "the form says the stored 90 seconds as it is"
    assert got["untouched"] == "Nothing changed."
    assert got["priority"] is None and got["touched"] is None
    assert got["bad"] == "Thin repeats for a whole number of minutes, from 0 to 10080."


@needs_node
def test_the_form_refuses_what_the_server_would_before_it_asks(tmp_path):
    got = run("""
const chat = { ...W, target_kind: 'TELEGRAM_CHAT', target_ref: 'c:111' };
const out = {};
function problems(w, mutate) {
  const card = watchRow(w, true);
  all(card, (x) => x.textContent === 'Edit…')[0].listeners.click();
  const spec = card.lastSpec;
  const values = spec.fields.map((f) => f.value);
  mutate(values);
  return spec.check(values);
}
out.short = problems(W, (v) => { v[0] = ' ab '; });
out.blankName = problems(W, (v) => { v[0] = ''; });
out.noTerm = problems(W, (v) => { v[1] = ''; v[2] = ''; v[3] = ''; });
out.oneTermLeft = problems(W, (v) => { v[1] = ''; v[2] = ''; });
out.chatNoTerm = problems(chat, (v) => { v[1] = ''; v[2] = ''; v[3] = ''; });
out.windows = ['-1', '1.5', '10081', '', 'x'].map((m) => problems(W, (v) => { v[5] = m; }));
out.top = problems(W, (v) => { v[5] = '10080'; });
console.log(JSON.stringify({ out, calls }));
""", tmp_path)
    out = got["out"]
    assert got["calls"] == [], "nothing is sent that the form can refuse"
    assert out["short"] == out["blankName"] == "Name the watch, in at least 3 characters."
    assert out["noTerm"] == "Give the watch a keyword, a selector or a pattern, or it matches nothing."
    assert out["oneTermLeft"] is None, "one list may go while another still carries a term"
    assert out["chatNoTerm"] is None, "a chat watch may end with none: it fires on every message"
    assert out["windows"] == ["Thin repeats for a whole number of minutes, from 0 to 10080."] * 5
    assert out["top"] is None


@needs_node
def test_a_refusal_is_shown_in_the_form_and_a_fault_is_not_swallowed(tmp_path):
    """The shared row form, run for real: the server's sentence lands inside the form and the form
    stays open with what was typed; a thrown fault is shown too and does not close it."""
    got = run("""
const card = watchRow(W, true);
all(card, (x) => x.textContent === 'Edit…')[0].listeners.click();
const wrap = all(card, (x) => x.className.startsWith('row-inline'))[0];
const form = all(wrap, (x) => x.tag === 'form')[0];
const fields = all(form, (x) => x.tag === 'input' || x.tag === 'textarea' || x.tag === 'select');
const message = () => all(wrap, (x) => x.className === 'form-error')[0];
const open = () => card.children.includes(wrap);
const submit = () => form.listeners.submit({ preventDefault() {} });
const out = {};
await submit();
out.nothing = [message().textContent, calls.length];
fields[1].value = 'changed';
globalThis.apiAnswer = () => { throw new ApiError(409, 'This watch was changed by someone else '
  + 'while you were editing it. Reload it and try again.'); };
await submit();
out.refused = [message().textContent, open(), fields[1].value];
globalThis.apiAnswer = () => { throw new Error('boom'); };
await submit();
out.fault = [message().textContent, open()];
globalThis.apiAnswer = () => ({ changed: ['keywords'] });
await submit();
out.saved = [open(), calls.filter((c) => c.reload).length];
console.log(JSON.stringify(out));
""", tmp_path, extra=("rowForm",))
    assert got["nothing"] == ["Nothing changed.", 0]
    assert got["refused"] == [
        "This watch was changed by someone else while you were editing it. Reload it and try "
        "again.", True, "changed"]
    assert got["fault"] == ["Error: boom", True]
    assert got["saved"] == [False, 1], "a saved form closes and the list is read again"


# ---------------------------------------------------------------------------
# The listing
# ---------------------------------------------------------------------------

@needs_node
def test_the_listing_draws_the_controls_for_a_manager_and_not_for_a_reader(tmp_path):
    got = run("""
const body = { watches: [W, { ...W, id: 'W2', name: 'second', is_active: false }], count: 2,
  can_create: true, kinds: [], sources: [] };
globalThis.apiAnswer = () => body;
await loadWatches();
const manager = drawn.splice(0)[0][2];
body.can_create = false;
await loadWatches();
const reader = drawn.splice(0)[0][2];
console.log(JSON.stringify({ manager, reader }));
""", tmp_path, extra=("loadWatches", "paintWatchForm", "paintWatchSources", "paintWatchRef"))
    manager, reader = got["manager"], got["reader"]
    assert "Stop" in manager[0] and "Edit…" in manager[0] and "Resume" not in manager[0]
    assert "Resume" in manager[1] and "Edit…" in manager[1] and "Stop" not in manager[1]
    for row in reader:
        assert "Stop" not in row and "Resume" not in row and "Edit…" not in row, (
            "a reader is drawn the rows and no control")


def test_the_listing_passes_the_manager_answer_to_every_row():
    assert "watchRow(w, body.can_create)" in _fn("loadWatches")
    assert "can_create" in _fn("loadWatches")


# ---------------------------------------------------------------------------
# The shipped copy and the constants
# ---------------------------------------------------------------------------

def test_the_priorities_and_the_window_bound_are_the_ones_the_add_form_and_server_hold():
    from noctornal_api.collection import WATCH_MAX_SUPPRESS_S

    html = _html()
    box = html[html.index('id="col-watch-priority"'):html.index('id="col-watch-window"')]
    markup = [(v, " ".join(t.split())) for v, t in
              re.findall(r'<option value="(\d)"[^>]*>([^<]*)</option>', box)]
    shipped = re.search(r"const WATCH_PRIORITIES = (\[.*\]);", _js()).group(1)
    assert [tuple(p) for p in json.loads(shipped.replace("'", '"'))] == markup, (
        "the Edit form says the priorities as the Add form does")
    assert f"const WATCH_MAX_MINUTES = {WATCH_MAX_SUPPRESS_S // 60};" in _js()


def test_the_new_copy_has_no_dash_and_no_bracketed_plural():
    for name in ("watchRow", "watchActions", "watchEdit", "editWatchForm"):
        literals, _ = js_tokens(_fn(name))
        assert literals, name
        for _, said in literals:
            assert "(s)" not in said, (name, said)
            assert not re.search("[\\u2013\\u2014]", said), (name, said)
            assert not re.search(r"\s--\s", said), (name, said)
    for name in ("WATCH_PRIORITIES", "WATCH_MAX_MINUTES"):
        literals, _ = js_tokens(_const(name))
        for _, said in literals:
            assert "(s)" not in said and not re.search("[\\u2013\\u2014]", said), (name, said)


def test_no_innerHTML_and_no_inline_style_in_the_new_functions():
    """Text only, through `el` and `textContent`, under the strict CSP: no markup from a string, no
    style attribute, no handler attribute, nothing evaluated."""
    banned = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
              "new Function", ".style", "setAttribute('style'", 'setAttribute("style"',
              "setAttribute('on", "srcdoc")
    for name in ("watchRow", "watchActions", "watchEdit", "editWatchForm"):
        source = _fn(name)
        for what in banned:
            assert what not in source, f"{name} uses {what}"
        assert not re.search(r"\bon[a-z]+\s*=", source), f"{name} sets a handler attribute"
