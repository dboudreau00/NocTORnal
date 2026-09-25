"""The MyBB pages, parsed (F4, 2026-09-24).

Pure, golden-file: saved MyBB 1.8 pages under tests/fixtures/mybb, on hosts
nobody can register, installed under /community/. Linear and threaded
views, a board, a profile and a no-permission page; and the one sharp
difference from XenForo, times printed in the board's own zone, read only
under a declared zone and formats.
"""
from __future__ import annotations

from datetime import datetime, timezone

from forum_helpers import MB_CONFIG, page

from noctornal_api import forum_parse as fp

NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)


def parse(kind: str, name: str, config=None, **kw) -> dict:
    return fp.parse_page("mybb", kind, page(f"mybb/{name}"), now=NOW,
                         config=MB_CONFIG if config is None else config, **kw)


def test_a_linear_thread_page_reads_to_its_posts():
    out = parse("thread", "showthread_linear.html")
    assert out["state"] == "ok" and out["drift"] == []
    assert (out["title"], out["current"], out["last"]) == ("Selling fullz, US and EU", 1, 2)
    assert [(p["id"], p["number"], p["handle"], p["uid"]) for p in out["posts"]] == [
        (120, 1, "bulletproof", 7), (121, 2, "buyer_one", 9), (122, 3, "bulletproof", 7)]


def test_quotes_and_signatures_are_cut_out():
    first = parse("thread", "showthread_linear.html")["posts"][0]
    assert first["quoted"] == ["post:99"]
    assert "quoted@xmpp.example.test" not in first["body"]
    assert "own@xmpp.example.test" in first["body"]
    assert first["signature"] == "ICQ 000000 | jabber sig@xmpp.example.test"
    assert "sig@xmpp.example.test" not in first["body"]


def test_times_are_read_in_the_declared_zone_title_first():
    posts = parse("thread", "showthread_linear.html")["posts"]
    # Riga is UTC+3 in September.
    assert [p["posted_at"] for p in posts] == [
        "2026-09-08T08:05:00+00:00",   # 09-08-2026, 11:05 AM
        "2026-09-10T13:12:00+00:00",   # Today (titled 09-10-2026), 04:12 PM
        "2026-09-10T14:40:00+00:00"]   # 5 Minutes Ago, titled 09-10-2026, 05:40 PM


def test_the_other_day_order_reads_other_days_and_no_zone_reads_nothing():
    swapped = parse("thread", "showthread_linear.html",
                    {**MB_CONFIG, "date_format": "d-m-Y"})["posts"]
    assert swapped[0]["posted_at"].startswith("2026-08-09")
    bare = parse("thread", "showthread_linear.html", {})["posts"]
    assert all(p["posted_at"] is None and p["date_state"] == "unanchored" for p in bare)
    wrong_clock = parse("thread", "showthread_linear.html",
                        {**MB_CONFIG, "time_format": "H:i"})["posts"]
    assert all(p["date_state"] == "unreadable" for p in wrong_clock)
    assert all(p["posted_at"] is None for p in wrong_clock), "never midnight instead"


def test_the_quick_login_box_does_not_make_a_thread_a_wall():
    assert parse("thread", "showthread_linear.html")["state"] == "ok"


def test_a_no_permission_page_is_a_wall():
    assert parse("thread", "nopermission.html") == {"state": "login"}


def test_the_threaded_view_still_reads_its_one_post():
    """The adapter always asks for mode=linear (test_forum_parse); should a
    board answer with its threaded view anyway, the one post it shows is
    read, not mistaken for drift."""
    out = parse("thread", "showthread_threaded.html")
    assert [p["id"] for p in out["posts"]] == [121] and out["drift"] == []


def test_an_edit_changes_the_body_and_a_removed_post_is_absent():
    before = {p["id"]: p for p in parse("thread", "showthread_page2.html")["posts"]}
    after = {p["id"]: p for p in parse("thread", "showthread_page2_later.html")["posts"]}
    assert before[131]["body"] != after[131]["body"]
    assert 130 in before and 130 not in after


def test_a_board_lists_its_threads_with_their_last_activity():
    out = parse("board", "forumdisplay.html")
    assert out["drift"] == []
    assert [t["id"] for t in out["threads"]] == [12, 13, 14]
    assert out["threads"][0]["last_activity"] == "2026-09-10T14:40:00+00:00"
    # 'Yesterday' titled 09-09-2026, 08:15 PM after the span.
    assert out["threads"][1]["last_activity"] == "2026-09-09T17:15:00+00:00"


def test_a_profile_reads_its_rows_and_never_the_login_box():
    out = parse("member", "member_7.html")
    assert (out["handle"], out["title"]) == ("bulletproof", "Verified vendor")
    assert out["fields"]["Jabber"] == "own@xmpp.example.test"
    assert "Username" not in out["fields"] and "Password" not in out["fields"]
    assert "own@xmpp.example.test" in out["body"]
    assert "212" not in out["body"], "a counter is not what a version is judged on"


def test_each_post_keeps_its_own_fragment_without_its_form_key():
    for post in parse("thread", "showthread_linear.html")["posts"]:
        assert post["raw"].startswith('<div class="post')
        assert "3b4c5d6e7f8091a2b3c4d5e6f7081920" not in post["raw"]
