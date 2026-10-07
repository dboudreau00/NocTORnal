"""What a feed poll does not keep is said, never dropped (beta 1 gate 6,
2026-10-07; invariant 12).

An item with no guid, id, link or title was skipped without a word, and a
feed had no cap on its items: a 16 MiB feed of bare items was some 600,000
documents in one transaction, every poll. Both are now a run warning, and
a poll reads at most `MAX_FEED_ITEMS`. Pure: the fetch is replaced.
"""
from __future__ import annotations

from noctornal_api import collection


def _feed(items: list[str]) -> bytes:
    return ("<?xml version='1.0'?><rss><channel>" + "".join(items)
            + "</channel></rss>").encode()


def _poll(monkeypatch, body: bytes):
    monkeypatch.setattr(collection, "fetch",
                        lambda url, **_kw: (body, 200, None, None))
    return collection.RssAdapter().fetch(base_url="https://feed.example/rss")


def test_an_item_with_nothing_to_tell_it_apart_is_a_warning_not_a_silent_drop(monkeypatch):
    result = _poll(monkeypatch, _feed([
        "<item><guid>a-1</guid><title>one</title></item>",
        "<item><description>no id at all</description></item>"]))
    assert [i.external_id for i in result.items] == ["a-1"]
    assert [w.kind for w in result.warnings] == [collection.ITEM_SKIPPED]
    assert "1 item of the feed carried no guid" in result.warnings[0].text


def test_a_feed_is_read_to_its_cap_and_says_what_it_left(monkeypatch):
    n = collection.MAX_FEED_ITEMS + 100
    result = _poll(monkeypatch, _feed([f"<item><guid>g{i}</guid></item>" for i in range(n)]))
    assert len(result.items) == collection.MAX_FEED_ITEMS
    assert result.items[0].external_id == "g0"
    assert [w.kind for w in result.warnings] == [collection.ITEM_SKIPPED]
    assert result.warnings[0].text.startswith("100 items were past the 500")


def test_parse_rss_still_answers_its_items():
    assert [i.external_id for i in collection.parse_rss(_feed(
        ["<item><guid>x</guid></item>"]))] == ["x"]
