"""F53 (docs/17, 2026-10-08): the Collected tab's Watches section, as the
console ships it.

The list and the Add a watch form sit in the Feeds pane's Collected tab, under
the hits the watches produce. Pure: no database. The markup is read from the
shipped index.html; the functions marked `needs_node` run under Node over the
same stub DOM the Sources tests use, and are judged by what they draw and what
they send. The server half is test_collection_watch_create_pg.py, and the
closed-case table (test_closed_case_read_only.py) holds that the box is one of
the controls a read-only case turns off.
"""
from __future__ import annotations

import json
import re

import pytest

from test_collection_ui_foundation import _const, _fn, _run
from test_ui_copy_no_dashes import NODE, _html, _js, js_tokens

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

IDS = (
    "col-watch-refresh", "col-watch-counts", "col-watch-list", "col-watch-empty",
    "col-watch-box", "col-watch-form", "col-watch-source", "col-watch-name",
    "col-watch-kind", "col-watch-ref-label", "col-watch-ref", "col-watch-keywords",
    "col-watch-selectors", "col-watch-regexes", "col-watch-priority",
    "col-watch-window", "col-watch-btn", "col-watch-chat-help", "col-watch-error",
    "col-watch-ok")

CONTROLS = ("col-watch-source", "col-watch-name", "col-watch-kind", "col-watch-ref",
            "col-watch-keywords", "col-watch-selectors", "col-watch-regexes",
            "col-watch-priority", "col-watch-window")

#: What every Node test starts from: one case open, a case counter the tests
#: can move, and the list helpers the pane shares with the rest of the console.
PRELUDE = r"""
state.caseId = 'C1';
let seq = 1;
globalThis.caseToken = () => seq;
globalThis.caseChanged = (t) => t !== seq;
globalThis.bump = () => { seq += 1; };
globalThis.cpath = (s) => '/cases/C1' + s;
const drawn = [];
globalThis.renderList = (list, empty, rows, build) => {
  drawn.push([list, empty, rows.map((r) => text(build(r)))]); };
globalThis.showLoadFailure = (id, what) => { drawn.push(['failed', id, what]); };
globalThis.listRefused = (id, said) => { drawn.push(['refused', id, said]); };
globalThis.refusalText = (err, context) => context;
globalThis.clearLoadFailure = () => {};
const go = { preventDefault() {} };
function fill(values) { for (const k of Object.keys(values)) $(k).value = values[k]; }
"""

FORM = """{
  'col-watch-source': 'S1', 'col-watch-name': '  nightjar  ',
  'col-watch-kind': 'FEED', 'col-watch-ref': ' https://feeds.example.test/a.xml ',
  'col-watch-keywords': ' ransom \\n\\n recruiting\\n', 'col-watch-selectors': 'a@b.test',
  'col-watch-regexes': '', 'col-watch-priority': '2', 'col-watch-window': '30',
}"""

WATCH = {"id": "W1", "name": "nightjar", "source_id": "S1", "source_name": "feed one",
         "source_kind": "RSS", "source_active": True, "target_kind": "FEED",
         "target_ref": "https://feeds.example.test/a.xml", "keywords": ["a", "b"],
         "selectors": ["s@x.test"], "regexes": ["p+"], "priority": 2,
         "suppress_window_s": 1800, "is_active": True, "created_at": "2026-10-08T00:00:00Z",
         "last_hit_at": None}

SOURCES = [
    {"id": "S1", "name": "Feed", "kind": "RSS", "is_active": True, "chat": None},
    {"id": "S2", "name": "Chat A", "kind": "TELEGRAM", "is_active": True, "chat": "c:111"},
    {"id": "S3", "name": "Chat B", "kind": "TELEGRAM", "is_active": False, "chat": "g:222"},
    {"id": "S4", "name": "Unresolved", "kind": "TELEGRAM", "is_active": True, "chat": None},
]


# ---------------------------------------------------------------------------
# The markup
# ---------------------------------------------------------------------------

def test_every_field_exists_once_inside_the_collected_tab():
    html = _html()
    block = html[html.index('id="feeds-collected"'):html.index('id="feeds-queue"')]
    for ident in IDS:
        assert html.count(f'id="{ident}"') == 1, ident
        assert f'id="{ident}"' in block, f"#{ident} is outside the Collected tab"


def test_the_watches_sit_between_the_hits_and_the_documents():
    html = _html()
    order = [html.index(f'id="{i}"') for i in
             ("col-hits-list", "col-watch-list", "col-watch-box", "col-doc-list")]
    assert order == sorted(order), order


def test_every_control_is_inside_a_label_and_the_box_is_one_form():
    html = _html()
    box = html[html.index('id="col-watch-box"'):html.index('id="col-watch-ok"')]
    assert box.count("<form") == 1 and box.count("</form>") == 1
    for ident in CONTROLS:
        at = box.index(f'id="{ident}"')
        label = box.rindex("<label", 0, at)
        assert "</label>" not in box[label:at], f"#{ident} is not inside its label"
        assert 'class="label"' in box[label:at], f"#{ident} has no visible label"
    assert re.search(r'<button id="col-watch-btn" type="submit"', box)
    assert 'role="alert"' in box[box.index('id="col-watch-error"') - 40:]


def test_the_markup_carries_no_inline_style_handler_or_script():
    html = _html()
    block = html[html.index("F53 (2026-10-08): the watches themselves"):
                 html.index('id="col-doc-list"')]
    assert not re.search(r"\sstyle\s*=", block, re.I)
    assert not re.search(r"\son[a-z]+\s*=", block, re.I)
    assert "<script" not in block.lower()


def test_the_bounds_in_the_markup_are_the_servers():
    from noctornal_api.collection import (
        _WATCH_CHAT_REF,
        WATCH_MAX_REF_CHARS,
        WATCH_MAX_SUPPRESS_S,
        WATCH_TARGET_KINDS,
    )

    html = _html()

    def attrs(ident: str) -> str:
        at = html.index(f'id="{ident}"')
        return html[html.rindex("<", 0, at):html.index(">", at)]

    name = attrs("col-watch-name")
    assert 'minlength="3"' in name and 'maxlength="200"' in name
    assert f'maxlength="{WATCH_MAX_REF_CHARS}"' in attrs("col-watch-ref")
    window = attrs("col-watch-window")
    assert 'min="0"' in window and f'max="{WATCH_MAX_SUPPRESS_S // 60}"' in window
    box = html[html.index('id="col-watch-priority"'):html.index('id="col-watch-window"')]
    assert re.findall(r'<option value="(\d)"', box) == ["1", "2", "3", "4", "5"]
    hint = re.search(r'data-hint-chat="([^"]+)"', attrs("col-watch-ref")).group(1)
    assert _WATCH_CHAT_REF.fullmatch(hint), "the example id is one the server takes"
    words = re.search(r"const WATCH_KIND_WORDS = \{(.*?)\};", _js(), re.S).group(1)
    assert set(re.findall(r"(\w+):", words)) == set(WATCH_TARGET_KINDS), (
        "every kind the server offers has a word, and the console names no other")


def test_the_markup_says_what_the_section_is_for():
    said = re.sub(r"\s+", " ", _html())
    assert "A watch is a standing tasking against one source." in said
    assert "documents already collected are not matched again" in said
    assert "the collector reads the source's own address and does not visit this one" in said
    assert "never by an @name, because a name can be given to someone else" in said
    assert "Not loaded for this case yet." in said


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def test_the_section_is_wired_at_boot_and_loaded_with_the_hits():
    js = _js()
    for wire in ("$('col-watch-refresh').addEventListener('click', loadWatches);",
                 "$('col-watch-form').addEventListener('submit', addWatch);",
                 "$('col-watch-kind').addEventListener('change', paintWatchSources);",
                 "$('col-watch-source').addEventListener('change', paintWatchRef);",
                 "if (name === 'collected') { loadWatchHits(); loadWatches(); }"):
        assert wire in js, wire


def test_every_function_the_section_uses_exists_and_the_box_is_a_content_control():
    js = _js()
    for name in ("loadWatches", "watchRow", "watchWindowText", "paintWatchForm",
                 "paintWatchSources", "paintWatchRef", "watchLines", "addWatch"):
        _fn(name)
    block = js[js.index("const CASE_CONTENT_CONTROLS = ["):]
    assert "'col-watch-box'" in block[:block.index("];")]


def test_the_new_copy_has_no_dash_and_no_bracketed_plural():
    names = ("loadWatches", "watchRow", "watchWindowText", "paintWatchForm",
             "paintWatchSources", "paintWatchRef", "addWatch")
    for name in names:
        literals, _ = js_tokens(_fn(name))
        assert literals, name
        for _, said in literals:
            assert "(s)" not in said, (name, said)
            assert not re.search("[\\u2013\\u2014]", said), (name, said)
            assert not re.search(r"\s--\s", said), (name, said)
    html = _html()
    block = html[html.index("F53 (2026-10-08): the watches themselves"):
                 html.index('id="col-doc-list"')]
    assert not re.search("[" + chr(0x2013) + chr(0x2014) + r"]|\(s\)", block)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

@needs_node
def test_a_listing_draws_the_rows_and_the_form_only_for_a_caller_who_may_add(tmp_path):
    got = _run(["loadWatches", "watchRow", "watchWindowText", "paintWatchForm",
                "paintWatchSources", "paintWatchRef"], PRELUDE + f"""
const body = {{ watches: [{json.dumps(WATCH)}], count: 1, can_create: true,
  kinds: ['BOARD', 'TELEGRAM_CHAT'], sources: {json.dumps(SOURCES)} }};
globalThis.apiAnswer = () => body;
await loadWatches();
await loadWatches();
const out = {{ drawn: drawn.slice(), counts: $('col-watch-counts').textContent,
  boxHidden: $('col-watch-box').hidden,
  kinds: $('col-watch-kind').children.map((o) => o.value + '=' + o.textContent),
  asked: calls.map((c) => c.path) }};
drawn.length = 0;
body.can_create = false; body.sources = [];
await loadWatches();
out.reader = {{ boxHidden: $('col-watch-box').hidden }};
body.watches = []; body.can_create = true; body.sources = {json.dumps(SOURCES)};
await loadWatches();
out.none = $('col-watch-empty').textContent;
body.can_create = false;
await loadWatches();
out.noneReader = $('col-watch-empty').textContent;
console.log(JSON.stringify(out));
""", tmp_path, consts=["WATCH_KIND_WORDS", "WATCH_CHAT_KIND", "COL_WATCHES_NOT_LOADED",
                       "WATCH"])
    assert got["asked"] == ["/cases/C1/collection/watches"] * 2
    assert got["drawn"][0][:2] == ["col-watch-list", "col-watch-empty"]
    row = got["drawn"][0][2][0]
    assert "nightjar" in row and "keywords: a, b" in row
    assert got["counts"] == "1 watch" and got["boxHidden"] is False
    assert got["kinds"] == ["BOARD=Board", "TELEGRAM_CHAT=Telegram chat"], (
        "the kinds are drawn once, however often the list is read")
    assert got["reader"] == {"boxHidden": True}, "a reader is drawn the list and no form"
    assert got["none"] == "No watch is set on this case yet. Add one below."
    assert got["noneReader"] == "No watch is set on this case yet."


@needs_node
def test_a_refused_or_failed_listing_says_so_and_offers_no_form(tmp_path):
    got = _run(["loadWatches", "watchRow", "watchWindowText", "paintWatchForm",
                "paintWatchSources", "paintWatchRef"], PRELUDE + """
$('col-watch-box').hidden = false;
globalThis.apiAnswer = () => { throw new ApiError(403, 'missing permission'); };
await loadWatches();
const refused = { drawn: drawn.splice(0), box: $('col-watch-box').hidden };
$('col-watch-box').hidden = false;
globalThis.apiAnswer = () => { throw new ApiError(500, 'boom'); };
await loadWatches();
const failed = { drawn: drawn.splice(0), box: $('col-watch-box').hidden,
  empty: $('col-watch-empty').textContent };
globalThis.apiAnswer = () => { bump(); return { watches: [], can_create: true, kinds: [], sources: [] }; };
await loadWatches();
console.log(JSON.stringify({ refused, failed, stale: drawn.splice(0) }));
""", tmp_path, consts=["WATCH_KIND_WORDS", "WATCH_CHAT_KIND", "COL_WATCHES_NOT_LOADED",
                       "WATCH"])
    assert got["refused"]["drawn"][-1] == [
        "refused", "col-watch-empty", "Watches need collection.read on this case."]
    assert got["refused"]["box"] is True
    assert got["failed"]["drawn"][-1][:2] == ["failed", "col-watch-empty"]
    assert got["failed"]["box"] is True
    assert got["failed"]["empty"] == "Not loaded for this case yet."
    assert got["stale"] == [], "an answer for a case that has been left draws nothing"


@needs_node
def test_a_case_switch_takes_the_list_the_form_and_what_was_typed(tmp_path):
    js = _js()
    start = js.index("onCaseSwitch(() => {\n  clear($('col-watch-list'));")
    handler = js[start:js.index("\n});", start) + 4]
    got = _run([], PRELUDE + f"""
const registered = [];
function onCaseSwitch(fn) {{ registered.push(fn); }}
{handler}
const resets = [];
$('col-watch-form').reset = () => resets.push('reset');
$('col-watch-box').open = true;
$('col-watch-box').hidden = false;
$('col-watch-list').children = [mk('div')];
$('col-watch-counts').textContent = '3 watches';
$('col-watch-error').textContent = 'x';
$('col-watch-ok').textContent = 'y';
WATCH.form = {{ sources: [1] }};
registered[0]();
console.log(JSON.stringify({{ list: $('col-watch-list').children.length,
  counts: $('col-watch-counts').textContent, empty: $('col-watch-empty').textContent,
  emptyShown: !$('col-watch-empty').hidden, resets, open: $('col-watch-box').open,
  boxHidden: $('col-watch-box').hidden, error: $('col-watch-error').textContent,
  ok: $('col-watch-ok').textContent, form: WATCH.form }}));
""", tmp_path, consts=["WATCH_KIND_WORDS", "WATCH_CHAT_KIND", "COL_WATCHES_NOT_LOADED",
                       "WATCH"])
    assert got == {"list": 0, "counts": "", "empty": "Not loaded for this case yet.",
                   "emptyShown": True, "resets": ["reset"], "open": False,
                   "boxHidden": True, "error": "", "ok": "", "form": None}


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

@needs_node
def test_a_watch_row_says_what_it_looks_at_how_it_thins_and_what_it_names(tmp_path):
    got = _run(["watchRow", "watchWindowText"], PRELUDE + f"""
const w = {json.dumps(WATCH)};
const plain = watchRow(w);
const stopped = watchRow({{ ...w, is_active: false, source_active: false,
  suppress_window_s: 0, last_hit_at: '2026-10-08T01:00:00Z' }});
const seconds = watchRow({{ ...w, suppress_window_s: 90 }});
const minute = watchRow({{ ...w, suppress_window_s: 60 }});
const chat = watchRow({{ ...w, target_kind: 'TELEGRAM_CHAT', target_ref: 'c:111',
  keywords: [], selectors: [], regexes: [] }});
const idle = watchRow({{ ...w, keywords: [], selectors: [], regexes: [] }});
console.log(JSON.stringify({{ plain: [text(plain), chips(plain)],
  stopped: [text(stopped), chips(stopped)], seconds: text(seconds),
  minute: text(minute), chat: text(chat), idle: text(idle) }}));
""", tmp_path, consts=["WATCH_KIND_WORDS", "WATCH_CHAT_KIND"])
    said, chips = got["plain"]
    for part in ("nightjar", "source: feed one", "looks at: https://feeds.example.test/a.xml",
                 "thinning: one hit per thread each 30 minutes", "last hit: none yet",
                 "keywords: a, b", "selectors: s@x.test", "patterns: p+", "Watch W1"):
        assert part in said, part
    assert chips == ["chip small:Feed", "chip small:priority 2"]
    said, chips = got["stopped"]
    assert "chip:stopped" in chips and "chip warn:source paused" in chips
    assert "thinning: none: a hit for every match" in said
    assert "last hit: T(2026-10-08T01:00:00Z)" in said
    assert "each 90 seconds" in got["seconds"] and "each 1 minute" in got["minute"]
    assert "chat: c:111" in got["chat"]
    assert "No term: this watch fires on every message of its chat." in got["chat"]
    assert "No term: this watch matches nothing." in got["idle"]
    assert "keywords:" not in got["chat"] and "keywords:" not in got["idle"]


# ---------------------------------------------------------------------------
# The form
# ---------------------------------------------------------------------------

@needs_node
def test_the_sources_offered_follow_the_kind_and_a_chat_fills_its_own_id(tmp_path):
    got = _run(["paintWatchSources", "paintWatchRef"], PRELUDE + f"""
WATCH.form = {{ sources: {json.dumps(SOURCES)} }};
const ref = $('col-watch-ref');
ref.placeholder = 'https://example.test/';
ref.dataset.hintChat = 'c:1234567890';
const options = () => $('col-watch-source').children.map((o) => o.value + '=' + o.textContent);
const out = {{}};
$('col-watch-kind').value = 'FEED';
paintWatchSources();
out.feed = options();
out.feedRef = [ref.value, ref.readOnly, ref.placeholder, $('col-watch-ref-label').textContent,
  $('col-watch-chat-help').hidden];
ref.value = 'a note I typed';
paintWatchRef();
out.noteKept = ref.value;
$('col-watch-kind').value = 'TELEGRAM_CHAT';
paintWatchSources();
out.chat = options();
out.chatHelp = !$('col-watch-chat-help').hidden;
$('col-watch-source').value = 'S2';
paintWatchRef();
out.chatRef = [ref.value, ref.readOnly, ref.placeholder, $('col-watch-ref-label').textContent];
$('col-watch-source').value = 'S3';
paintWatchRef();
out.otherChat = ref.value;
$('col-watch-kind').value = 'BOARD';
paintWatchSources();
out.back = [ref.value, ref.readOnly, ref.placeholder, options().length];
WATCH.form = {{ sources: [] }};
$('col-watch-kind').value = 'TELEGRAM_CHAT';
paintWatchSources();
out.noChats = options();
$('col-watch-kind').value = 'FEED';
paintWatchSources();
out.noSources = options();
console.log(JSON.stringify(out));
""", tmp_path, consts=["WATCH_CHAT_KIND", "WATCH"])
    assert got["feed"] == ["S1=Feed", "S2=Chat A", "S3=Chat B (paused)", "S4=Unresolved"]
    assert got["feedRef"] == ["", False, "https://example.test/", "Address or id", True]
    assert got["noteKept"] == "a note I typed"
    assert got["chat"] == ["S2=Chat A", "S3=Chat B (paused)"], (
        "only a Telegram source that reads a chat can take a chat watch")
    assert got["chatHelp"] is True
    assert got["chatRef"] == ["c:111", True, "c:1234567890", "Chat"]
    assert got["otherChat"] == "g:222"
    assert got["back"] == ["", False, "https://example.test/", 4], (
        "an id the chat mode wrote is not left as a note for another kind")
    assert got["noChats"] == ["=No Telegram chat is added"]
    assert got["noSources"] == ["=No source is available"]


@needs_node
def test_the_form_refuses_what_the_server_would_before_it_asks(tmp_path):
    got = _run(["addWatch", "watchLines"], PRELUDE + f"""
globalThis.loadWatches = () => calls.push({{ reload: 'watches' }});
const base = {FORM};
const out = [];
async function attempt(over) {{
  fill({{ ...base, ...over }});
  await addWatch(go);
  out.push($('col-watch-error').textContent);
}}
await attempt({{ 'col-watch-source': '' }});
await attempt({{ 'col-watch-name': ' ab ' }});
await attempt({{ 'col-watch-ref': '  ' }});
await attempt({{ 'col-watch-keywords': ' \\n ', 'col-watch-selectors': '' }});
await attempt({{ 'col-watch-window': '-1' }});
await attempt({{ 'col-watch-window': '1.5' }});
await attempt({{ 'col-watch-window': '10081' }});
await attempt({{ 'col-watch-kind': 'TELEGRAM_CHAT', 'col-watch-ref': '' }});
console.log(JSON.stringify({{ out, calls }}));
""", tmp_path, consts=["WATCH_CHAT_KIND"])
    assert got["calls"] == [], "nothing is sent that the form can refuse"
    assert got["out"] == [
        "Choose the source this watch reads.",
        "Name the watch, in at least 3 characters.",
        "Say what the watch looks at: an address or an id.",
        "Give the watch a keyword, a selector or a pattern, or it matches nothing.",
        "Thin repeats for a whole number of minutes, from 0 to 10080.",
        "Thin repeats for a whole number of minutes, from 0 to 10080.",
        "Thin repeats for a whole number of minutes, from 0 to 10080.",
        "Choose a Telegram source that reads a chat."]


@needs_node
def test_a_submit_sends_exactly_the_fields_the_server_takes_and_reloads(tmp_path):
    from noctornal_api.http.routers.collection import WatchCreate

    got = _run(["addWatch", "watchLines"], PRELUDE + f"""
globalThis.loadWatches = () => calls.push({{ reload: 'watches' }});
globalThis.apiAnswer = () => ({{ watch: {{}}, next: 'It applies from the next poll.' }});
fill({FORM});
await addWatch(go);
const first = {{ calls: calls.splice(0), name: $('col-watch-name').value,
  terms: ['col-watch-keywords', 'col-watch-selectors', 'col-watch-regexes'].map((i) => $(i).value),
  ok: $('col-watch-ok').textContent, error: $('col-watch-error').hidden,
  busy: $('col-watch-btn').disabled, ref: $('col-watch-ref').value }};
fill({{ ...{FORM}, 'col-watch-kind': 'TELEGRAM_CHAT', 'col-watch-ref': 'c:111',
  'col-watch-keywords': '', 'col-watch-selectors': '' }});
await addWatch(go);
console.log(JSON.stringify({{ first, chat: calls.splice(0) }}));
""", tmp_path, consts=["WATCH_CHAT_KIND"])
    sent = got["first"]["calls"]
    assert sent[1] == {"reload": "watches"}
    post = sent[0]
    assert post["path"] == "/cases/C1/collection/watches"
    assert post["opts"]["method"] == "POST"
    assert post["opts"]["json"] == {
        "source_id": "S1", "name": "nightjar", "target_kind": "FEED",
        "target_ref": "https://feeds.example.test/a.xml",
        "keywords": ["ransom", "recruiting"], "selectors": ["a@b.test"], "regexes": [],
        "priority": 2, "suppress_window_s": 1800}
    assert set(post["opts"]["json"]) == set(WatchCreate.model_fields), (
        "the console sends the fields the route's body names, and no other")
    first = got["first"]
    assert first["name"] == "" and first["terms"] == ["", "", ""]
    assert first["ok"] == "Added. It applies from the next poll."
    assert first["error"] is True and first["busy"] is False
    assert first["ref"].strip() == "https://feeds.example.test/a.xml", (
        "what it looks at stays for the next watch on the same address")
    chat = got["chat"][0]["opts"]["json"]
    assert chat["target_kind"] == "TELEGRAM_CHAT" and chat["target_ref"] == "c:111"
    assert chat["keywords"] == chat["selectors"] == chat["regexes"] == [], (
        "a chat watch with no term is sent as it is: it fires on every message")


@needs_node
def test_a_refusal_is_shown_in_the_form_and_a_server_fault_is_not_swallowed(tmp_path):
    got = _run(["addWatch", "watchLines"], PRELUDE + f"""
globalThis.loadWatches = () => calls.push({{ reload: 'watches' }});
const out = {{}};
fill({FORM});
globalThis.apiAnswer = () => {{ throw new ApiError(409, 'This case already has a watch with that name.'); }};
await addWatch(go);
out.refused = [$('col-watch-error').textContent, $('col-watch-name').value, $('col-watch-btn').disabled];
globalThis.apiAnswer = () => {{ throw new ApiError(500, 'boom'); }};
try {{ await addWatch(go); out.fault = 'swallowed'; }} catch (e) {{ out.fault = e.status; }}
out.busy = $('col-watch-btn').disabled;
out.reloads = calls.filter((c) => c.reload).length;
console.log(JSON.stringify(out));
""", tmp_path, consts=["WATCH_CHAT_KIND"])
    assert got["refused"] == ["This case already has a watch with that name.", "  nightjar  ", False]
    assert got["fault"] == 500 and got["busy"] is False and got["reloads"] == 0


@needs_node
def test_an_answer_for_a_case_that_has_been_left_changes_nothing(tmp_path):
    got = _run(["addWatch", "watchLines"], PRELUDE + f"""
globalThis.loadWatches = () => calls.push({{ reload: 'watches' }});
fill({FORM});
globalThis.apiAnswer = () => {{ bump(); return {{ watch: {{}}, next: 'n' }}; }};
await addWatch(go);
console.log(JSON.stringify({{ name: $('col-watch-name').value, ok: $('col-watch-ok').textContent,
  reloads: calls.filter((c) => c.reload).length, busy: $('col-watch-btn').disabled }}));
""", tmp_path, consts=["WATCH_CHAT_KIND"])
    assert got == {"name": "  nightjar  ", "ok": "", "reloads": 0, "busy": False}


def test_the_node_runs_use_the_shipped_constants():
    """The Node tests above load the constants from app.js itself, so a
    renamed one fails here and not as a silent pass."""
    for name in ("WATCH_KIND_WORDS", "WATCH_CHAT_KIND", "COL_WATCHES_NOT_LOADED", "WATCH"):
        assert _const(name)
