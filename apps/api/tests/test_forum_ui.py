"""The console's forum lines (F3 and F4, 2026-09-24).

Pure: no database. The Add a source form's forum settings (shown for the
two forum parsers, MyBB's zone and formats for MyBB alone, bounded as the
server bounds them), the MyBB format lists held equal to the server's, the
Poll now confirmation when a read would leave from this server, and the
Forum details a collected forum document offers. Functions run under Node
over the collection foundation tests' stub DOM.
"""
from __future__ import annotations

import re

import pytest

from test_collection_ui_foundation import _fn, _run
from test_ui_copy_no_dashes import NODE, _html, _js

from noctornal_api import forum_parse

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

FORUM_IDS = ("src-add-pages-field", "src-add-pages", "src-add-recheck-field",
             "src-add-recheck", "src-add-members-field", "src-add-members",
             "src-add-zone-field", "src-add-zone", "src-add-datefmt-field",
             "src-add-datefmt", "src-add-timefmt-field", "src-add-timefmt",
             "src-add-forum-help")


def _array(name: str) -> str:
    """The literal of `const NAME = [...];`, which may span lines (the
    collection foundation's helper reads a multi-line constant only up to
    a closing brace)."""
    m = re.search(rf"(?m)^const {re.escape(name)} = (\[[^;]*?\]);", _js())
    assert m, f"{name} is gone"
    return m.group(1)


def _markup() -> str:
    html = _html()
    start = html.index("<!-- F3 and F4 (2026-09-24)")
    return html[start:html.index("</details>", start)]


def test_every_forum_field_exists_once_hidden_until_a_forum_parser_is_chosen():
    html = _html()
    for ident in FORUM_IDS:
        assert html.count(f'id="{ident}"') == 1, ident
    for ident in FORUM_IDS:
        if ident.endswith("-field") or ident == "src-add-forum-help":
            tag = re.search(rf'<[a-z]+ id="{ident}"[^>]*>', html).group(0)
            assert " hidden" in tag, ident


def test_the_forum_markup_carries_no_inline_style_or_handler():
    markup = _markup()
    assert "style=" not in markup and not re.search(r"\son[a-z]+=", markup)


def test_the_forum_copy_keeps_the_console_rules():
    markup = _markup()
    words = re.sub(r"<[^>]+>", " ", markup)
    assert "\u2014" not in words and "\u2013" not in words and " -- " not in words
    assert "(s)" not in words
    help_text = " ".join(words.split())
    assert "NocTORnal-collector" in help_text and "never from this server" in help_text
    assert "no posting time is stored" in help_text


def test_the_mybb_formats_are_exactly_the_servers():
    js = _js()
    for name, server in (("MYBB_DATE_FORMATS", forum_parse.DATE_FORMATS),
                         ("MYBB_TIME_FORMATS", forum_parse.TIME_FORMATS)):
        assert re.findall(r"'([^']+)'", _array(name)) == list(server), name
    assert "const FORUM_PARSERS = ['xenforo', 'mybb'];" in js


def _globals() -> str:
    """The forum constants, as globals the extracted functions can see."""
    return "".join(f"globalThis.{name} = {_array(name)};\n" for name in (
        "FORUM_PARSERS", "MYBB_DATE_FORMATS", "MYBB_TIME_FORMATS"))


def test_the_form_sends_the_forum_settings_and_paints_the_fields():
    assert "paintForumFields(a);" in _fn("paintSourceKinds")
    add = _fn("addSource")
    assert "const forum = forumConfig(a);" in add
    assert "if (forum.config) json.parser_config = forum.config;" in add


@needs_node
def test_the_fields_show_for_a_forum_parser_and_the_zone_for_mybb_alone(tmp_path):
    got = _run(["paintForumFields"], _globals() + r"""
const shown = (a) => { paintForumFields(a); return Object.fromEntries(
  ['src-add-pages-field', 'src-add-zone-field', 'src-add-forum-help']
    .map((id) => [id, !$(id).hidden])); };
$('src-add-url').placeholder = 'https://board.example.test/forums/7/';
$('src-add-forum-help').dataset = { hintXenforo: 'XF', hintMybb: 'MB' };
const out = { rss: shown({ parser_key: 'rss' }) };
out.xenforo = shown({ parser_key: 'xenforo' });
out.xfHint = $('src-add-url').placeholder;
out.mybb = shown({ parser_key: 'mybb' });
out.mbHint = $('src-add-url').placeholder;
out.none = shown(null);
out.back = $('src-add-url').placeholder;
out.dates = $('src-add-datefmt').children.map((o) => o.value);
console.log(JSON.stringify(out));
""", tmp_path)
    off = {"src-add-pages-field": False, "src-add-zone-field": False,
           "src-add-forum-help": False}
    assert got["rss"] == off and got["none"] == off
    assert got["xenforo"] == {"src-add-pages-field": True, "src-add-zone-field": False,
                              "src-add-forum-help": True}
    assert got["mybb"] == {"src-add-pages-field": True, "src-add-zone-field": True,
                           "src-add-forum-help": True}
    assert (got["xfHint"], got["mbHint"]) == ("XF", "MB")
    assert got["back"] == "https://board.example.test/forums/7/"
    assert got["dates"] == list(forum_parse.DATE_FORMATS)


@needs_node
def test_the_settings_are_bounded_as_the_server_bounds_them(tmp_path):
    got = _run(["forumConfig"], _globals() + r"""
const set = (pages, recheck, members, zone) => {
  $('src-add-pages').value = pages; $('src-add-recheck').value = recheck;
  $('src-add-members').value = members; $('src-add-zone').value = zone;
  $('src-add-datefmt').value = 'd.m.Y'; $('src-add-timefmt').value = 'H:i'; };
const out = [];
set('5', '2', '0', ''); out.push(forumConfig({ parser_key: 'rss' }));
out.push(forumConfig({ parser_key: 'xenforo' }));
set('21', '2', '0', ''); out.push(forumConfig({ parser_key: 'xenforo' }));
set('5', '6', '0', ''); out.push(forumConfig({ parser_key: 'xenforo' }));
set('5', '2', '1.5', ''); out.push(forumConfig({ parser_key: 'xenforo' }));
set('5', '2', '0', '  '); out.push(forumConfig({ parser_key: 'mybb' }));
set('5', '2', '1', ' Europe/Riga '); out.push(forumConfig({ parser_key: 'mybb' }));
console.log(JSON.stringify(out));
""", tmp_path)
    assert got[0] == {"config": None}
    assert got[1] == {"config": {"page_budget": 5, "recheck_pages": 2, "member_pages": 0}}
    assert got[2]["error"] == "Pages per poll is a whole number from 1 to 20."
    assert got[3]["error"] == "Pages rechecked is a whole number from 0 to 5."
    assert got[4]["error"] == "Member pages per poll is a whole number from 0 to 10."
    assert "time zone" in got[5]["error"]
    assert got[6] == {"config": {"page_budget": 5, "recheck_pages": 2, "member_pages": 1,
                                 "timezone": "Europe/Riga", "date_format": "d.m.Y",
                                 "time_format": "H:i"}}


@needs_node
def test_poll_now_says_when_a_forum_read_leaves_from_this_server(tmp_path):
    got = _run(["authorityPollText", "srcExitWords", "personaLabel"], r"""
SRC.form = { sources: [{ id: 'S1', egress_profile: { id: 'E1', name: 'exit-one' } }],
  forum_reads_direct: true };
SRC.personas = [];
const s = { id: 'S1', name: 'Board', parser_key: 'xenforo', max_rps: 0.5,
  run_seconds: 90, persona: null };
const direct = authorityPollText(s, 'board.example.test');
SRC.form.forum_reads_direct = false;
const proxied = authorityPollText(s, 'board.example.test');
console.log(JSON.stringify([direct, proxied]));
""", tmp_path, consts=["SRC"])
    direct, proxied = got
    assert "from this server\u2019s own address, with no egress proxy configured" in direct
    assert "exit-one" not in direct
    assert "through egress profile exit-one" in proxied
    assert "NocTORnal-collector" in direct and "NocTORnal-collector" in proxied


@needs_node
def test_a_forum_document_offers_its_details_and_draws_them_as_facts(tmp_path):
    got = _run(["collectedDocRow", "documentHoldActions", "forumDetailsControl",
                "forumDetailFacts"], r"""
const base = { id: 'D1', title: 't', triage_state: 'NEW', classification: 'AMBER',
  source_name: 's', author_handle: 'a', posted_at: null, version: 1 };
const rss = collectedDocRow({ ...base, source_kind: 'RSS' });
const forum = collectedDocRow({ ...base, source_kind: 'XENFORO' });
globalThis.apiAnswer = () => ({ kind: 'post', signature_text: 'Jabber: sig@x.example.test',
  quoted_post_refs: ['post:9'], reactions: { count: 3, reactors: ['Alice'] },
  observed_at: '2026-09-10T10:00:00+00:00' });
await find(forum, (x) => x.tag === 'button').listeners.click();
const post = text(forum);
const member = forumDetailFacts({ kind: 'member', profile: { title: 'Seller',
  fields: { Jabber: 'own@x.example.test' } } }).map(text).join(' | ');
console.log(JSON.stringify({ rss: buttons(rss), forum: buttons(forum), post, member,
  calls: calls.filter((c) => c.path) }));
""", tmp_path)
    assert got["rss"] == [] and got["forum"] == ["Forum details"]
    assert "signature: Jabber: sig@x.example.test" in got["post"]
    assert "describes the author" in got["post"]
    assert "quotes: post:9" in got["post"]
    assert "reactions: 3 reactions, shown: Alice" in got["post"]
    assert "Jabber: own@x.example.test" in got["member"] and "title: Seller" in got["member"]
    assert got["calls"] == [{"path": "/collection/documents/D1/forum", "opts": None}]
