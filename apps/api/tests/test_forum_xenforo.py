"""The XenForo pages, parsed (F3, 2026-09-24).

Pure, golden-file: saved XenForo 2 pages under tests/fixtures/xenforo, on
hosts nobody can register, parsed exactly as the bounded child parses
them. What each post is, who wrote it, when, what it quotes and what its
signature says; a board's listing; a member's profile; a sign-in page, an
anti-bot page and a restyled page told apart.
"""
from __future__ import annotations

from datetime import datetime, timezone

from forum_helpers import page

from noctornal_api import forum_parse as fp

NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)


def parse(kind: str, name: str, **kw) -> dict:
    return fp.parse_page("xenforo", kind, page(f"xenforo/{name}"), now=NOW, **kw)


def test_a_thread_page_reads_to_its_posts_in_order():
    out = parse("thread", "thread_page1.html")
    assert out["state"] == "ok" and out["drift"] == []
    assert (out["title"], out["current"], out["last"], out["slug"]) == (
        "[WTS] Fresh dumps, track 1+2", 1, 3, "wts-fresh-dumps")
    assert [p["id"] for p in out["posts"]] == [1001, 1002, 1003]
    assert [p["number"] for p in out["posts"]] == [1, 2, 3]


def test_the_author_handle_and_the_author_id_are_read_apart():
    first, second, guest = parse("thread", "thread_page1.html")["posts"]
    assert (first["handle"], first["uid"]) == ("carder_kid", 42)
    assert (second["handle"], second["uid"]) == ("vendor_x", 55)
    assert (guest["handle"], guest["uid"]) == ("guest_user", None), (
        "a guest's data-user-id 0 is no member")


def test_a_post_time_is_the_instant_the_page_prints_in_utc():
    first = parse("thread", "thread_page1.html")["posts"][0]
    assert first["posted_at"] == "2026-09-08T08:15:00+00:00"
    assert first["date_state"] == "ok"


def test_a_quoted_address_is_never_the_quoters():
    first = parse("thread", "thread_page1.html")["posts"][0]
    assert "quoted@xmpp.example.test" not in first["body"]
    assert "own@xmpp.example.test" in first["body"]
    assert first["quoted"] == ["post:999"]


def test_the_signature_is_cut_from_the_body_and_kept_once():
    first = parse("thread", "thread_page1.html")["posts"][0]
    assert first["signature"] == "Jabber: sig@xmpp.example.test | escrow only"
    assert "sig@xmpp.example.test" not in first["body"]


def test_the_reactions_bar_gives_a_count_and_the_names_shown():
    vouch = parse("thread", "thread_page1.html")["posts"][1]
    assert vouch["reactions"] == {"count": 5, "reactors": ["Alice", "Bob"],
                                  "types": ["Like"]}


def test_each_post_keeps_its_own_fragment_without_its_form_token():
    posts = parse("thread", "thread_page1.html")["posts"]
    for post in posts:
        raw = post["raw"]
        assert raw.startswith("<article") and f'data-content="post-{post["id"]}"' in raw
        assert "9f0e3c1b2a7d6e5f4a3b2c1d0e9f8a7b" not in raw
    assert "Fresh batch in" not in posts[1]["raw"], "never another post's markup"


def test_an_edit_changes_the_body_and_a_removed_post_is_absent():
    before = {p["id"]: p for p in parse("thread", "thread_page3.html")["posts"]}
    after = {p["id"]: p for p in parse("thread", "thread_page3_later.html")["posts"]}
    assert before[1041]["body"] != after[1041]["body"]
    assert "sold out" in after[1041]["body"]
    assert 1042 in before and 1042 not in after
    assert before[1043]["body"] == after[1043]["body"]


def test_the_page_number_is_the_one_the_page_says_it_is():
    out = parse("thread", "thread_page3.html")
    assert (out["current"], out["last"]) == (3, 3)


def test_ids_the_parser_refuses_are_dropped_and_counted():
    out = parse("thread", "thread_hostile_ids.html")
    assert [p["id"] for p in out["posts"]] == [1051]
    assert out["bad_ids"] == 2


def test_a_board_lists_numeric_thread_ids_with_their_activity():
    out = parse("board", "board.html")
    assert out["drift"] == [] and (out["current"], out["last"]) == (1, 2)
    assert [(t["id"], t["slug"]) for t in out["threads"]] == [
        (1236, "rules-read-before-posting"), (1234, "wts-fresh-dumps"),
        (1235, "wtb-drops-eu")]
    assert out["threads"][1]["last_activity"] == "2026-09-10T16:05:00+00:00"


def test_an_empty_board_is_not_drift():
    out = parse("board", "board_empty.html")
    assert out["threads"] == [] and out["drift"] == []


def test_a_member_profile_reads_its_fields_and_leaves_counters_out_of_its_text():
    out = parse("member", "member_42.html")
    assert (out["uid"], out["handle"], out["title"]) == (42, "carder_kid", "Trusted seller")
    assert out["fields"]["Jabber"] == "own@xmpp.example.test"
    assert out["fields"]["Messages"] == "312"
    assert "own@xmpp.example.test" in out["body"] and "312" not in out["body"]


def test_a_sign_in_page_is_a_wall_and_a_challenge_is_a_challenge():
    assert parse("thread", "login.html", status=403) == {"state": "login"}
    assert parse("thread", "challenge.html", status=503) == {"state": "challenge"}
    assert parse("board", "login.html") == {"state": "login"}


def test_a_restyled_page_is_drift():
    out = parse("thread", "thread_restyled.html")
    assert out["posts"] == [] and out["drift"] == ["no_posts"]


def test_the_selector_is_a_valid_prefix_match():
    posts = fp._html(page("xenforo/thread_page1.html").decode()).css(
        'article.message[data-content^="post-"]')
    assert len(posts) == 3
