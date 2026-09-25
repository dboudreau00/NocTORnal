"""The XenForo and MyBB adapters without a database (F3 and F4, 2026-09-24).

The contract they register under, their settings and refusals, the
cursor, the deletion rule, a walk over a fake RunContext (pagination as a
hint, a forged page number, the first visit's order), the bounded child
(a page built to exhaust lexbor is abandoned at the wall clock), and the
production refusal of the development override. The walk through
run_once and the database is test_forum_collection_pg.py.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import forum_helpers as fh

from noctornal_api import forum_adapters as fa
from noctornal_api import forum_parse as fp
from noctornal_api.collection import BudgetSpent, CollectionError, SourceBlocked

NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)


# --- the contract ---------------------------------------------------------------

@pytest.mark.parametrize("cls, key, kind", [(fa.XenForoAdapter, "xenforo", "XENFORO"),
                                            (fa.MyBBAdapter, "mybb", "MYBB")])
def test_each_adapter_registers_under_the_collection_contract(cls, key, kind):
    a = cls()
    assert (a.key, a.version, a.source_kinds) == (key, "1", frozenset({kind}))
    assert a.requires_authority is True and a.persona_platform is None
    assert a.retention_clock is True and a.keeps_raw is True
    assert a.default_category == "FORUM_POST"
    assert a.run_seconds == 90.0 and a.max_page_bytes == 4 * 1024 * 1024
    assert a.max_run_bytes == 24 * 1024 * 1024
    assert a.min_interval_s == 900 and a.max_rps_cap == 0.5


def test_the_default_registry_carries_both_and_member_profiles_are_a_category():
    from noctornal_api import collection

    registry = collection.default_adapters()
    assert isinstance(registry["xenforo"], fa.XenForoAdapter)
    assert isinstance(registry["mybb"], fa.MyBBAdapter)
    assert "FORUM_MEMBER" in collection.DOCUMENT_CATEGORIES
    from noctornal_api.ingest import CATEGORIES
    assert "FORUM_MEMBER" not in CATEGORIES, "ingest keys cannot declare it"


# --- settings -----------------------------------------------------------------

def test_a_source_address_must_be_a_thread_or_a_board():
    assert fa.XenForoAdapter().validate_source(fh.XF_THREAD, {}) == []
    assert "neither a XenForo thread nor a board" in fa.XenForoAdapter().validate_source(
        f"{fh.XF_BASE}/search/?q=x", {})[0]
    assert fa.XenForoAdapter().validate_source(None, {}) == [
        "A forum source needs the address of a thread or a board."]


def test_a_mybb_source_needs_its_zone_and_both_formats():
    mybb = fa.MyBBAdapter()
    assert mybb.validate_source(fh.MB_THREAD, fh.MB_CONFIG) == []
    for missing in ("timezone", "date_format", "time_format"):
        config = {k: v for k, v in fh.MB_CONFIG.items() if k != missing}
        assert mybb.needs_times in mybb.validate_source(fh.MB_THREAD, config)


@pytest.mark.parametrize("config, words", [
    ({"page_budget": 0}, "Pages per poll is a whole number from 1 to 20."),
    ({"page_budget": 21}, "Pages per poll is a whole number from 1 to 20."),
    ({"page_budget": True}, "Pages per poll is a whole number from 1 to 20."),
    ({"recheck_pages": 6}, "Pages rechecked is a whole number from 0 to 5."),
    ({"member_pages": -1}, "Member pages per poll is a whole number from 0 to 10."),
    ({"shiny": 1}, "The parser settings carry 1 setting this parser does not read."),
    ({"timezone": "Europe/Riga"}, "The parser settings carry 1 setting this parser does not read."),
])
def test_xenforo_settings_are_bounded(config, words):
    assert words in fa.XenForoAdapter().validate_config(config)


@pytest.mark.parametrize("config, words", [
    ({"timezone": "Mars/Olympus"}, "time zone is not a zone name"),
    ({"date_format": "%Y"}, "date format is not one this parser reads"),
    ({"time_format": "HH"}, "time format is not one this parser reads"),
])
def test_mybb_zone_and_formats_are_from_the_allowed_lists(config, words):
    assert any(words in p for p in fa.MyBBAdapter().validate_config(config))


def test_a_page_budget_alone_is_accepted_as_runcontext_asks():
    for adapter in (fa.XenForoAdapter(), fa.MyBBAdapter()):
        assert adapter.validate_config({"page_budget": 7}) == []


def test_every_sentence_keeps_the_console_copy_rules():
    sentences = [v for k, v in vars(fa).items() if k.isupper() and isinstance(v, str)
                 and " " in v]
    sentences += [fa.XenForoAdapter.shape_sentence, fa.MyBBAdapter.shape_sentence,
                  fa.MyBBAdapter.needs_times, *fp.DRIFT_WORDS.values()]
    for text in sentences:
        assert "\u2014" not in text and "\u2013" not in text and " -- " not in text
        assert "(s)" not in text


# --- the direct route ----------------------------------------------------------

def test_with_no_proxy_a_forum_is_refused_unless_development_says_otherwise():
    assert fa.direct_refusal({}) == fa.DIRECT_REFUSED
    assert fa.direct_refusal({"NOCTORNAL_FORUM_ALLOW_DIRECT": "1"}) is None
    assert fa.direct_refusal({"NOCTORNAL_FORUM_ALLOW_DIRECT": "yes"}) == fa.DIRECT_REFUSED
    assert fa.direct_refusal({"NOCTORNAL_FORUM_ALLOW_DIRECT": "1",
                              "NOCTORNAL_ENV": "production"}) == fa.DIRECT_REFUSED
    assert fa.direct_refusal({"NOCTORNAL_EGRESS_PROXY_URL": "http://127.0.0.1:3128"}) is None
    assert fa.reads_direct({"NOCTORNAL_FORUM_ALLOW_DIRECT": "1"}) is True
    assert fa.reads_direct({"NOCTORNAL_FORUM_ALLOW_DIRECT": "1",
                            "NOCTORNAL_EGRESS_PROXY_URL": "http://127.0.0.1:3128"}) is False


def test_production_refuses_to_start_with_the_override_set():
    from noctornal_api.config import verify_environment

    sentence = ("NOCTORNAL_FORUM_ALLOW_DIRECT is set, and it lets a forum be read "
                "from this server's own address with no egress proxy; it exists for "
                "development only.")
    assert sentence in verify_environment({"NOCTORNAL_ENV": "production",
                                           "NOCTORNAL_FORUM_ALLOW_DIRECT": "1"})
    assert sentence not in verify_environment({"NOCTORNAL_ENV": "production"})
    assert verify_environment({"NOCTORNAL_FORUM_ALLOW_DIRECT": "1"}) == []


def test_the_parser_missing_is_refused_before_anything_else(monkeypatch):
    monkeypatch.setattr(fp, "parser_available", lambda: False)
    source = SimpleNamespace(base_url=fh.XF_THREAD, parser_config={})
    assert fa.XenForoAdapter().refusal(None, source) == fa.PARSER_MISSING


# --- fetch refuses before any request ------------------------------------------------

class FakeContext:
    """RunContext's surface as the walk uses it: fetch, pages_used,
    remaining, route.proxied, source.parser_config, and its budget."""

    def __init__(self, site, *, config=None, proxied=False, budget=20):
        self.site = site
        self.pages_used = 0
        self.budget = budget
        self.route = SimpleNamespace(proxied=proxied)
        self.source = SimpleNamespace(parser_config=config or {})

    def fetch(self, url, *, accept_status=frozenset(), max_bytes=None):
        if self.pages_used >= self.budget:
            raise BudgetSpent("spent")
        self.pages_used += 1
        return self.site(url, accept_status=accept_status)

    def remaining(self):
        return 60.0


def _fetch(site, base=fh.XF_THREAD, cursor=None, *, adapter=None, **kw):
    adapter = adapter or fa.XenForoAdapter(parse=fa.parse_in_process)
    return adapter.fetch(base_url=base, cursor=cursor, context=FakeContext(site, **kw))


def test_a_secret_or_a_missing_context_is_refused(monkeypatch):
    adapter = fa.XenForoAdapter(parse=fa.parse_in_process)
    with pytest.raises(CollectionError, match="without a persona or a credential"):
        adapter.fetch(base_url=fh.XF_THREAD, secret="hunter2", context=None)
    with pytest.raises(CollectionError, match="only inside a poll"):
        adapter.fetch(base_url=fh.XF_THREAD)


def test_a_direct_route_is_refused_at_the_last_step_too(monkeypatch):
    monkeypatch.delenv("NOCTORNAL_FORUM_ALLOW_DIRECT", raising=False)
    site = fh.xf_thread_site()
    with pytest.raises(SourceBlocked, match="own address"):
        _fetch(site)
    assert site.calls == []
    monkeypatch.setenv("NOCTORNAL_FORUM_ALLOW_DIRECT", "1")
    assert _fetch(site).items


# --- the walk ---------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _direct_allowed(monkeypatch, request):
    if request.node.name.startswith("test_a_direct_route"):
        return
    monkeypatch.setenv("NOCTORNAL_FORUM_ALLOW_DIRECT", "1")


def test_a_first_visit_reads_page_one_then_the_newest_pages_backwards():
    site = fh.xf_thread_site()
    got = _fetch(site)
    assert site.urls() == [fh.XF_THREAD, f"{fh.XF_THREAD}page-3", f"{fh.XF_THREAD}page-2"]
    thread = got.cursor["t"]["1234"]
    assert thread["p"] == 3 and thread["s"] == "wts-fresh-dumps"
    assert fa.decode_ids(thread["w"]) == [1001, 1002, 1003, 1021, 1022, 1023,
                                          1041, 1042, 1043]


def _forged(number: bytes) -> bytes:
    return fh.page("xenforo/thread_page1.html").replace(
        b'<a href="https://board.example.test/threads/wts-fresh-dumps.1234/page-3">3</a>',
        b'<a href="https://board.example.test/threads/wts-fresh-dumps.1234/page-'
        + number + b'">' + number + b"</a>")


def test_a_forged_last_page_moves_the_walk_one_real_page_at_a_time():
    """Page 1 claims 99,999 pages. The forum clamps the request for page
    99,999 to its real last page, which says it is page 3: that is the
    page number kept, and nothing past it is asked for."""
    site = fh.xf_thread_site(**{fh.XF_THREAD: (200, _forged(b"99999")),
                                f"{fh.XF_THREAD}page-99999": "xenforo/thread_page3.html"})
    got = _fetch(site)
    assert site.urls() == [fh.XF_THREAD, f"{fh.XF_THREAD}page-99999",
                           f"{fh.XF_THREAD}page-2"]
    assert got.cursor["t"]["1234"]["p"] == 3


def test_a_page_number_past_any_real_forum_is_not_believed():
    site = fh.xf_thread_site(**{fh.XF_THREAD: (200, _forged(b"999999"))})
    _fetch(site)
    assert all("999999" not in u for u in site.urls())


def test_a_later_visit_starts_recheck_pages_back_and_walks_forward():
    first = _fetch(fh.xf_thread_site())
    site = fh.xf_thread_site()
    _fetch(site, cursor=first.cursor, config={"recheck_pages": 1})
    assert site.urls() == [f"{fh.XF_THREAD}page-2", f"{fh.XF_THREAD}page-3"]


def test_the_walk_returns_what_it_read_when_the_budget_ends():
    got = _fetch(fh.xf_thread_site(), config={"page_budget": 2})
    assert {i.external_id for i in got.items} >= {"post:1001", "post:1041"}
    assert any(w.kind == "BUDGET_SPENT" for w in got.warnings)


def test_a_board_thread_behind_a_sign_in_is_skipped_not_fatal():
    site = fh.Site({fh.XF_BOARD: "xenforo/board.html",
                    fh.XF_THREAD: (403, "xenforo/login.html"),
                    f"{fh.XF_BASE}/threads/wtb-drops-eu.1235/": "xenforo/thread_page1.html"})
    got = _fetch(site, base=fh.XF_BOARD, config={"page_budget": 3})
    assert any(w.kind == "ITEM_SKIPPED" and "thread:1234" in w.text for w in got.warnings)
    assert got.items, "the next thread is read"


def test_a_redirect_to_another_site_blocks_the_source():
    site = fh.Site({fh.XF_THREAD: lambda url, **kw: fh.fetched(
        url, 302, location="https://elsewhere.example.test/x")})
    with pytest.raises(SourceBlocked, match="another site"):
        _fetch(site)


def test_a_same_origin_redirect_chain_that_runs_out_is_said_as_such():
    site = fh.Site({fh.XF_THREAD: lambda url, **kw: fh.fetched(
        url, 301, location=f"{fh.XF_BASE}/threads/elsewhere.9/")})
    with pytest.raises(SourceBlocked, match="more times than a poll follows"):
        _fetch(site)


def test_a_gone_thread_fails_and_a_503_with_retry_after_is_rate_limited():
    from noctornal_api.collection import RateLimited

    with pytest.raises(CollectionError, match="no longer exists"):
        _fetch(fh.Site({}))
    busy = fh.Site({fh.XF_THREAD: (503, b"<html><body>busy</body></html>",
                                   {"Retry-After": "120"})})
    with pytest.raises(RateLimited) as exc:
        _fetch(busy)
    assert exc.value.retry_after_s == 120.0


def test_a_drifting_run_reports_no_deletion():
    first = _fetch(fh.xf_thread_site())
    restyled = fh.xf_thread_site(**{f"{fh.XF_THREAD}page-2": "xenforo/thread_restyled.html"})
    got = _fetch(restyled, cursor=first.cursor)
    assert any(w.kind == "PARSER_DRIFT" for w in got.warnings)
    assert got.deleted_external_ids == []


def test_a_post_the_first_poll_saw_twice_is_one_item():
    doubled = fh.page("xenforo/thread_page2.html").replace(
        b'data-content="post-1021"', b'data-content="post-1041"')
    got = _fetch(fh.xf_thread_site(**{f"{fh.XF_THREAD}page-2": (200, doubled)}))
    ids = [i.external_id for i in got.items]
    assert len(ids) == len(set(ids))


# --- the deletion rule and the cursor ---------------------------------------------------

@pytest.mark.parametrize("previous, seen, gone", [
    ([1, 2, 3, 4], {1, 3, 4}, [2]),
    ([1, 2, 3, 4], {2, 3, 4}, []),          # 1 moved off the pages read
    ([1, 2, 3, 4], {1, 2, 3}, []),          # 4 moved on past them
    ([1, 2, 3, 4], {1, 4}, [2, 3]),
    ([1, 2], {5, 6}, []),                   # no survivor: nothing is judged
    ([1, 5], {1}, []),
    ([], {1, 2}, []),
])
def test_a_post_is_gone_only_between_two_survivors(previous, seen, gone):
    assert fa.gone_between_survivors(previous, seen) == gone


def test_ids_round_trip_through_the_cursor_encoding():
    ids = [1001, 1002, 1003, 1041, 9_007_199_254_740_991]
    assert fa.decode_ids(fa.encode_ids(ids)) == ids
    for garbage in ("zz,!!", "-5", "9" * 9000, 42, None):
        assert fa.decode_ids(garbage) == []


def test_the_cursor_stays_under_its_cap_dropping_the_oldest_first():
    threads = {tid: fa.ThreadState(page=tid % 900 + 1, window=list(range(tid * 100, tid * 100 + 60)),
                                   slug="a-long-thread-name-" + "x" * 40, activity=tid,
                                   visited=tid)
               for tid in range(1, 400)}
    cursor = fa.write_cursor(threads, list(range(1, 1000)))
    size = len(json.dumps(cursor, separators=(",", ":")))
    assert size <= fa.CURSOR_BYTES
    kept = cursor["t"]
    assert "399" in kept, "the most recently visited thread is kept"
    assert "1" not in kept
    back, members = fa.read_cursor(cursor)
    assert back[399].page == threads[399].page
    assert len(members) <= fa.MAX_CURSOR_MEMBERS


def test_a_malformed_cursor_costs_a_re_read_never_a_failure():
    threads, members = fa.read_cursor({"t": {"x": {}, "5": "no", "7": {"p": -3, "w": "!"}},
                                       "m": ["a", 3, True]})
    assert list(threads) == [7] and threads[7].page == 1 and threads[7].window == []
    assert members == [3]


# --- the bounded child -----------------------------------------------------------------

def test_the_child_parses_a_page_exactly_as_this_process_does():
    fetched = fh.fetched(fh.XF_THREAD, 200, fh.page("xenforo/thread_page1.html"))
    here = fa.parse_in_process("xenforo", "thread", fetched, config={}, now=NOW, wall_s=10)
    there = fa.parse_bounded("xenforo", "thread", fetched, config={}, now=NOW, wall_s=30)
    assert there == here


def test_a_cyrillic_page_near_the_size_cap_comes_back_whole():
    """Eight posts of about 0.46 MiB of Cyrillic each: escaped as \\u
    sequences the child's answer would be about 20 MiB and pass its 16 MiB
    cap, abandoning a page that parsed; as UTF-8 it is under 7 MiB."""
    word = "\u0434\u0430\u043c\u043f\u044b"
    body = word * (480_000 // len(word.encode()))
    posts = "".join(
        f'<article class="message" data-author="a" data-content="post-{i}">'
        f'<time datetime="2026-09-10T10:00:00+00:00"></time>'
        f'<div class="message-body"><div class="bbWrapper">{body}</div></div></article>'
        for i in range(1, 9))
    fetched = fh.fetched(fh.XF_THREAD, 200, posts.encode("utf-8"))
    assert len(fetched.body) < fp.MAX_PAGE_BYTES
    out = fa.parse_bounded("xenforo", "thread", fetched, config={}, now=NOW, wall_s=60)
    assert len(out["posts"]) == 8
    assert all(p["raw"] is not None and p["body"].startswith(word) for p in out["posts"])


def test_a_page_built_to_exhaust_the_parser_is_abandoned_at_the_wall_clock():
    """Repeated unclosed <a> within 4 MiB: lexbor's tree builder is
    quadratic on it (measured 2026-09-24: over 25 seconds). The child is
    killed at its wall clock and the page is abandoned, never waited on."""
    unit = "<a>" * 64 + "x" + "</a>" * 64
    hostile = (unit * (fp.MAX_PAGE_BYTES // len(unit)))[:fp.MAX_PAGE_BYTES].encode()
    fetched = fh.fetched(fh.XF_THREAD, 200, hostile)
    started = time.monotonic()
    with pytest.raises(fa.ParseAbandoned) as exc:
        fa.parse_bounded("xenforo", "thread", fetched, config={}, now=NOW, wall_s=3)
    assert exc.value.reason == "timeout"
    assert time.monotonic() - started < 20


@pytest.mark.parametrize("script, reason", [
    ("import sys; sys.stdin.buffer.read(); print('not json')", "bad_output"),
    ("import sys, json; sys.stdin.buffer.read(); print(json.dumps({'ok': False}))", "refused"),
    ("import sys; sys.stdin.buffer.read(); sys.exit(3)", "crashed"),
])
def test_a_child_that_answers_nothing_usable_is_abandoned(monkeypatch, script, reason):
    monkeypatch.setattr(fa, "CHILD_ARGV", [sys.executable, "-c", script])
    fetched = fh.fetched(fh.XF_THREAD, 200, b"<p>x</p>")
    with pytest.raises(fa.ParseAbandoned) as exc:
        fa.parse_bounded("xenforo", "thread", fetched, config={}, now=NOW, wall_s=20)
    assert exc.value.reason == reason


def test_an_abandoned_page_is_drift_and_holds_the_walk():
    def abandon(*_a, **_k):
        raise fa.ParseAbandoned("timeout")

    got = fa.XenForoAdapter(parse=abandon).fetch(
        base_url=fh.XF_THREAD, context=FakeContext(fh.xf_thread_site()))
    assert [w.text for w in got.warnings if w.kind == "PARSER_DRIFT"] == [fa.PARSE_ABANDONED]
    assert got.items == []
