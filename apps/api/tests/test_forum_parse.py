"""The forum parsing toolkit (F3 and F4, 2026-09-24).

Pure: no database, no socket. Ids, text, times, the URL model, quotes,
signatures, fragments, login walls, challenges and drift, over short
inline pages and hostile input built at run time (a fixture file may not
carry control or invisible characters: check_source_hygiene refuses them).
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path

import pytest

from noctornal_api import forum_parse as fp

SRC = Path(fp.__file__).resolve().parent
NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)


def tree(html: str):
    return fp._html(html)


# --- ids --------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["42", 42, " 42 ", "9007199254740991"])
def test_an_id_is_a_positive_ascii_whole_number_below_2_53(raw):
    assert fp.positive_id(raw) == int(str(raw).strip())


@pytest.mark.parametrize("raw", [
    "0", "-1", "9007199254740992", "42x", "", "4 2", "0x2a", "1e3", True, 4.2,
    None, "\u0663", "\uff14\uff12", "12345678901234567"])
def test_anything_else_is_refused(raw):
    with pytest.raises(fp.ForumParseError):
        fp.positive_id(raw)


def test_ids_are_typed_so_a_member_never_versions_a_post():
    assert fp.post_ref("42") == "post:42"
    assert fp.member_ref(42) == "member:42"
    assert fp.thread_ref("7") == "thread:7"
    assert fp.post_ref(42) != fp.member_ref(42)


# --- text -------------------------------------------------------------------

def test_normalising_removes_control_and_invisible_characters_and_collapses_space():
    hostile = "ab\u202ecd\u200b ef\x00\x07\n\n\t gh\ufeff"
    assert fp.normalise_ws(hostile) == "abcd ef gh"


def test_normalising_decodes_no_entity():
    assert fp.normalise_ws("5 &lt; 10 &amp; x") == "5 &lt; 10 &amp; x"


def test_the_parser_decodes_an_entity_exactly_once():
    node = tree("<div>typed &amp;lt;script&amp;gt; and &lt;b&gt;</div>").css_first("div")
    assert fp.node_text(node) == "typed &lt;script&gt; and <b>"


def test_block_text_never_glues_two_paragraphs_and_drops_scripts():
    node = tree("<div><p>a@x.example.test</p><p>Contact</p>line<br>next"
                "<script>alert('no')</script><style>p{}</style></div>").css_first("div")
    text = fp.block_text(node)
    assert "a@x.example.test Contact" in text and "line next" in text
    assert "alert" not in text and "p{}" not in text


@pytest.mark.parametrize("header, meta, text", [
    ("text/html; charset=windows-1251", b"", "\u0414\u0430"),
    (None, b'<meta charset="windows-1251">', "\u0414\u0430"),
    ("text/html; charset=x-no-such-codec", b"", "\ufffd\ufffd"),
])
def test_a_page_is_decoded_by_its_declared_charset_or_as_utf8(header, meta, text):
    body = meta + "\u0414\u0430".encode("windows-1251")
    assert text in fp.decode_page(body, header)


# --- times --------------------------------------------------------------------

def test_a_xenforo_instant_is_utc():
    assert fp.parse_instant("2026-09-10T16:12:00+0100") == datetime(
        2026, 9, 10, 15, 12, tzinfo=timezone.utc)
    assert fp.parse_instant("1789053120") == datetime(2026, 9, 10, 15, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("raw", [
    "2026-09-10T16:12:00", "yesterday", "1980-01-01T00:00:00+00:00",
    "2099-01-01T00:00:00+00:00", "9" * 40, "", None])
def test_anything_but_a_believable_instant_is_none(raw):
    assert fp.parse_instant(raw, now=NOW) is None


def test_the_same_mybb_date_reads_differently_under_the_two_orders():
    us = fp.parse_board_time("09-10-2026, 04:12 PM", tz="Europe/Riga",
                             date_format="m-d-Y", time_format="h:i A", now=NOW)
    eu = fp.parse_board_time("09-10-2026, 04:12 PM", tz="Europe/Riga",
                             date_format="d-m-Y", time_format="h:i A",
                             now=datetime(2026, 10, 12, tzinfo=timezone.utc))
    assert us == datetime(2026, 9, 10, 13, 12, tzinfo=timezone.utc)
    assert eu == datetime(2026, 10, 9, 13, 12, tzinfo=timezone.utc)
    assert us.date() != eu.date()


@pytest.mark.parametrize("tz, fmt", [(None, "m-d-Y"), ("Europe/Riga", None),
                                     ("", "m-d-Y"), ("Europe/Riga", "Y%m")])
def test_a_mybb_time_without_both_declared_is_none(tz, fmt):
    assert fp.parse_board_time("09-10-2026, 04:12 PM", tz=tz, date_format=fmt,
                               time_format="h:i A", now=NOW) is None


@pytest.mark.parametrize("raw", ["Today, 04:12 PM", "5 Minutes Ago", "2 hours ago"])
def test_a_relative_form_is_never_anchored(raw):
    assert fp.parse_board_time(raw, tz="Europe/Riga", date_format="m-d-Y",
                               time_format="h:i A", now=NOW) is None


def test_a_date_alone_is_refused_where_a_clock_is_required():
    kw = {"tz": "Europe/Riga", "date_format": "m-d-Y", "time_format": "h:i A", "now": NOW}
    assert fp.parse_board_time("09-10-2026", **kw) is not None
    assert fp.parse_board_time("09-10-2026", require_time=True, **kw) is None


@pytest.mark.parametrize("name", ["../../etc/passwd", "/etc/localtime", "Europe/../../x",
                                  "C:\\Windows", "Not/AZone", "a" * 200])
def test_a_zone_name_is_checked_before_it_is_looked_up(name):
    assert fp.zone(name) is None


# --- where a source is --------------------------------------------------------

@pytest.mark.parametrize("url, kind, ident, prefix, style, slug", [
    ("https://board.example.test/threads/wts-dumps.1234/", "thread", 1234, "/", "path", "wts-dumps"),
    ("https://board.example.test/threads/1234/page-3", "thread", 1234, "/", "path", None),
    ("https://board.example.test/community/forums/market.7/", "board", 7, "/community/", "path", "market"),
    ("https://board.example.test/index.php?threads/x.9/", "thread", 9, "/index.php", "query", "x"),
    ("http://board.example.onion:8080/forums/3/", "board", 3, "/", "path", None),
])
def test_a_xenforo_address_is_read_by_its_shape(url, kind, ident, prefix, style, slug):
    loc = fp.locate("xenforo", url)
    assert (loc.kind, loc.id, loc.prefix, loc.style, loc.slug) == (kind, ident, prefix, style, slug)


@pytest.mark.parametrize("url, kind, ident, prefix", [
    ("https://forum.example.test/showthread.php?tid=12", "thread", 12, "/"),
    ("https://forum.example.test/community/showthread.php?tid=12&page=3", "thread", 12, "/community/"),
    ("https://forum.example.test/forumdisplay.php?fid=3", "board", 3, "/"),
    ("https://forum.example.test/board/thread-12.html", "thread", 12, "/board/"),
    ("https://forum.example.test/forum-3-page-2.html", "board", 3, "/"),
])
def test_a_mybb_address_is_read_by_its_shape(url, kind, ident, prefix):
    loc = fp.locate("mybb", url)
    assert (loc.kind, loc.id, loc.prefix) == (kind, ident, prefix)


@pytest.mark.parametrize("platform, url", [
    ("xenforo", "https://board.example.test/members/carder_kid.42/"),
    ("xenforo", "https://board.example.test/"),
    ("xenforo", "https://user:pw@board.example.test/threads/1/"),
    ("xenforo", "ftp://board.example.test/threads/1/"),
    ("xenforo", "https://board.example.test:99999/threads/1/"),
    ("xenforo", "https://board.example.test/threads/99999999999999999999/"),
    ("mybb", "https://forum.example.test/member.php?action=profile&uid=7"),
    ("mybb", "https://forum.example.test/showthread.php?tid=abc"),
    ("mybb", "https://forum.example.test/showthread.php?" + "&".join(f"a{i}=1" for i in range(40))),
    ("vbulletin", "https://forum.example.test/showthread.php?tid=1"),
])
def test_anything_else_is_not_a_source_address(platform, url):
    assert fp.locate(platform, url) is None


def test_every_url_is_built_on_the_source_origin_and_install_path():
    xf = fp.locate("xenforo", "https://board.example.test/community/threads/x.1/")
    assert fp.thread_page_url(xf, 55, 1, "wts") == \
        "https://board.example.test/community/threads/wts.55/"
    assert fp.thread_page_url(xf, 55, 4) == "https://board.example.test/community/threads/55/page-4"
    assert fp.member_page_url(xf, 42) == "https://board.example.test/community/members/42/about"
    q = fp.locate("xenforo", "https://board.example.test/index.php?forums/m.7/")
    assert fp.board_page_url(q, 2) == "https://board.example.test/index.php?forums/m.7/page-2"
    mb = fp.locate("mybb", "https://forum.example.test/community/forumdisplay.php?fid=3")
    assert fp.thread_page_url(mb, 12, 2) == \
        "https://forum.example.test/community/showthread.php?tid=12&mode=linear&page=2"
    assert fp.board_page_url(mb, 1) == "https://forum.example.test/community/forumdisplay.php?fid=3"
    assert fp.member_page_url(mb, 7) == \
        "https://forum.example.test/community/member.php?action=profile&uid=7"


def test_mybb_threads_are_always_asked_for_in_linear_mode():
    mb = fp.locate("mybb", "https://forum.example.test/showthread.php?tid=12&mode=threaded")
    for page in (1, 2, 9):
        assert "mode=linear" in fp.thread_page_url(mb, 12, page)


@pytest.mark.parametrize("bad", ["12/../../admin", "http://evil.example/", -1, 0, "1 OR 1"])
def test_a_builder_takes_validated_ids_only(bad):
    loc = fp.locate("xenforo", "https://board.example.test/threads/1/")
    with pytest.raises(fp.ForumParseError):
        fp.thread_page_url(loc, bad)


def test_a_slug_that_is_not_a_slug_is_left_out_of_a_built_url():
    loc = fp.locate("xenforo", "https://board.example.test/threads/1/")
    assert fp.thread_page_url(loc, 5, 1, "../../x") == "https://board.example.test/threads/5/"


@pytest.mark.parametrize("platform, what, href, want", [
    ("xenforo", "thread", "/threads/wts-dumps.1234/", (1234, "wts-dumps")),
    ("xenforo", "member", "https://board.example.test/members/kid.42/", (42, "kid")),
    ("mybb", "member", "member.php?action=profile&uid=7", (7, None)),
    ("mybb", "member", "/community/user-7.html", (7, None)),
    ("mybb", "thread", "showthread.php?tid=12&pid=99#pid99", (12, None)),
    ("mybb", "thread", "x" * 3000, None),
    ("xenforo", "thread", "/threads/99999999999999999999/", None),
])
def test_an_href_is_read_for_its_id_only(platform, what, href, want):
    assert fp.id_from_href(platform, what, href) == want


# --- quotes, signatures, fragments --------------------------------------------

def test_quotes_are_cut_out_and_only_the_outermost_is_named():
    html = ('<div class="bbWrapper">mine@x.example.test '
            '<blockquote data-source="post: 9">theirs@x.example.test'
            '<blockquote data-source="post: 8">deeper@x.example.test</blockquote>'
            '</blockquote> after</div>')
    clone = tree(html).css_first("div").clone()
    assert fp.strip_quotes(clone, "xenforo") == ["post:9"]
    text = fp.block_text(clone)
    assert "mine@x.example.test" in text and "after" in text
    assert "theirs" not in text and "deeper" not in text


def test_a_mybb_quote_is_named_by_the_post_its_cite_links_to():
    html = ('<div class="post_body">own <blockquote class="mycode_quote"><cite>'
            'Old Wrote: <a href="showthread.php?pid=99#pid99" class="quick_jump"></a>'
            '</cite>quoted</blockquote></div>')
    clone = tree(html).css_first("div").clone()
    assert fp.strip_quotes(clone, "mybb") == ["post:99"]
    assert fp.block_text(clone) == "own"


def test_a_page_of_quotes_is_capped_and_every_quote_still_goes():
    html = "<div>" + "".join(f'<blockquote data-source="post: {i}">q{i}</blockquote>'
                             for i in range(1, 300)) + "own</div>"
    clone = tree(html).css_first("div").clone()
    refs = fp.strip_quotes(clone, "xenforo")
    assert len(refs) == fp.MAX_QUOTED
    assert fp.block_text(clone) == "own"


def test_a_signature_is_kept_apart_from_the_body():
    html = ('<article><div class="bbWrapper">body <div class="message-signature">'
            'planted@x.example.test</div></div><aside class="message-signature">'
            'Jabber: sig@x.example.test<br>escrow</aside></article>')
    post = tree(html).css_first("article")
    assert fp.signature_text(post, "xenforo") == (
        "planted@x.example.test Jabber: sig@x.example.test escrow")
    body = post.css_first(".bbWrapper").clone()
    fp.strip_signature(body, "xenforo")
    assert fp.block_text(body) == "body"


def test_a_fragment_keeps_the_post_and_drops_every_token_and_control():
    html = ('<article data-content="post-5"><a href="/react?x=1&amp;_xfToken=abc123secret">L</a>'
            '<a href="member.php?action=logout&amp;logoutkey=feedface">out</a>'
            '<form action="/r"><input type="hidden" name="_xfToken" value="abc123secret"></form>'
            '<script>var my_post_key = "beefcafe";</script><p>text</p></article>')
    raw = fp.fragment(tree(html).css_first("article"))
    assert b"post-5" in raw and b"<p>text</p>" in raw
    for leaked in (b"abc123secret", b"feedface", b"beefcafe", b"<form", b"<input", b"<script"):
        assert leaked not in raw


def test_a_fragment_larger_than_one_mebibyte_is_not_kept():
    html = "<article>" + "<p>" + "x" * (fp.MAX_FRAGMENT_BYTES + 10) + "</p></article>"
    assert fp.fragment(tree(html).css_first("article")) is None


# --- what kind of answer ------------------------------------------------------

def test_a_login_template_and_a_do_login_page_are_walls():
    xf = tree('<html id="XF" data-template="login"><body><form action="/login/login">'
              '<input type="password"></form></body></html>')
    assert fp.is_login_wall("xenforo", xf, status=403)
    mb = tree('<div id="content"><form><input name="action" value="do_login">'
              '<input type="password" name="password"></form></div>')
    assert fp.is_login_wall("mybb", mb, status=200)


def test_the_quick_login_box_on_every_mybb_guest_page_is_not_a_wall():
    page = tree('<div class="modal" id="quick_login"><form><input name="action" value="do_login">'
                '<input type="password"></form></div><div id="posts"><div class="post" '
                'id="post_1"></div></div>')
    assert not fp.is_login_wall("mybb", page, status=200)
    board = tree('<div class="modal" id="quick_login"><input type="password"></div>'
                 '<span id="tid_12">x</span>')
    assert not fp.is_login_wall("mybb", board, status=200, page_kind="board")


@pytest.mark.parametrize("url", ["https://board.example.test/login/",
                                 "https://forum.example.test/member.php?action=login",
                                 "https://board.example.test/index.php?login/"])
def test_a_sign_in_address_is_a_wall_whatever_the_page(url):
    assert fp.login_url(url)
    assert fp.is_login_wall("xenforo", tree("<p>hi</p>"), status=200, url=url)


def test_a_challenge_is_told_from_a_board_that_mentions_one():
    challenge = "<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/x'></script></html>"
    assert fp.is_challenge("xenforo", challenge, tree(challenge))
    board = ('<html id="XF"><body><div class="p-body">a post about '
             'ddos-guard and cf_chl_ tokens</div></body></html>')
    assert not fp.is_challenge("xenforo", board, tree(board))


# --- drift and bounds ------------------------------------------------------------

def test_a_thread_page_with_no_post_the_parser_knows_is_drift():
    out = fp.parse_page("xenforo", "thread", b"<html id='XF'><body><div class='p-body'>"
                        b"<div class='post-new'>x</div></div></body></html>", now=NOW)
    assert out["state"] == "ok" and out["drift"] == ["no_posts"]


def test_posts_with_no_author_are_drift():
    posts = "".join(f'<article class="message" data-content="post-{i}"><div class="message-body">'
                    f'<div class="bbWrapper">b</div></div><time datetime="2026-09-10T10:00:00+00:00">'
                    f'</time></article>' for i in range(1, 4))
    out = fp.parse_page("xenforo", "thread", posts.encode(), now=NOW)
    assert "no_authors" in out["drift"]


def test_a_page_is_read_for_at_most_two_hundred_posts():
    posts = "".join(f'<article class="message" data-author="a" data-content="post-{i}">'
                    f'<time datetime="2026-09-10T10:00:00+00:00"></time>b</article>'
                    for i in range(1, 260))
    out = fp.parse_page("xenforo", "thread", posts.encode(), now=NOW)
    assert len(out["posts"]) == fp.MAX_POSTS and out["dropped_posts"] == 59


def test_a_page_over_four_mebibytes_is_refused_unread():
    with pytest.raises(fp.ForumParseError):
        fp.parse_page("xenforo", "thread", b"x" * (fp.MAX_PAGE_BYTES + 1))


@pytest.mark.parametrize("body", [
    b"", b"\x00\x01\x02" * 1000, b"<" * 50_000, b"\xff\xfe" + "abc".encode("utf-16-le"),
    b"<article class='message' data-content='post-1'>" * 3000,
    ("<div title='" + "\u202e" * 1000 + "'>").encode(),
], ids=["empty", "control", "angles", "utf16", "unclosed-articles", "bidi-attribute"])
def test_hostile_bytes_parse_to_plain_data_or_drift_never_an_error(body):
    out = fp.parse_page("xenforo", "thread", body, now=NOW)
    assert out["state"] in ("ok", "login", "challenge")


def test_an_unknown_platform_or_page_kind_is_refused():
    with pytest.raises(fp.ForumParseError):
        fp.parse_page("phpbb", "thread", b"<p>x</p>")
    with pytest.raises(fp.ForumParseError):
        fp.parse_page("xenforo", "search", b"<p>x</p>")


# --- the one parser dependency ------------------------------------------------------

@pytest.mark.parametrize("module", ["forum_parse.py", "forum_adapters.py"])
def test_only_the_lexbor_backend_is_ever_imported(module):
    """selectolax 0.4.12's package __init__ imports its modest backend too,
    so a runtime sys.modules check proves nothing: this reads the source.
    Neither module names selectolax.parser, selectolax.modest or the
    modest HTMLParser class (LGPL-2.1, deprecated)."""
    source = (SRC / module).read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            assert node.module in (None, "__future__") or not node.module.startswith(
                "selectolax") or node.module == "selectolax.lexbor", node.module
            assert all(a.name != "HTMLParser" for a in node.names)
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("selectolax") or alias.name == "selectolax.lexbor"
        if isinstance(node, ast.Attribute):
            assert node.attr not in ("modest", "parser") or not (
                isinstance(node.value, ast.Name) and node.value.id == "selectolax")
