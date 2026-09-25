"""RunContext: one poll's budgets, pacing, origin rule, redirects, 429s and
custody log (the collection foundation, 2026-09-24). No database, no
network: a fake fetcher stands in for collection.fetch_response, a fake
clock for time.
"""
from __future__ import annotations

import http.client
from uuid import uuid4

import pytest

BASE = "https://board.example.test/forums/7/"


def _source(**over):
    from noctornal_api.collection import SourceRow

    values = dict(id=uuid4(), kind="XENFORO", name="b0ctx", base_url=BASE,
                  parser_key="stubforum", classification="AMBER",
                  default_reliability="C", max_rps=10.0, is_active=True,
                  collection_account_id=None, egress_profile_id=None,
                  parser_config={}, blocked_reason=None, cursor_reset_at=None)
    values.update(over)
    return SourceRow(**values)


class Adapter:
    key = "stubforum"
    requires_authority = True
    run_seconds = 60.0
    max_pages = 10
    max_page_bytes = 1000
    max_run_bytes = 5000
    persona_min_gap_s = 2.0

    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, v)


class Limiter:
    def __init__(self):
        self.calls = []

    def wait(self, source_id, max_rps):
        self.calls.append(("source", max_rps))

    def wait_persona(self, persona_id, gap):
        self.calls.append(("persona", gap))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _fetched(url, status=200, body=b"<html>ok</html>", location=None):
    from noctornal_api.pinned_http import Fetched

    return Fetched(status, http.client.HTTPMessage(), body, url, "text/html",
                   None, None, 0, "DIRECT", "127.0.0.1", location)


class Fetcher:
    """Answers by URL from a script; records every call."""

    def __init__(self, answers=None, default=None):
        self.answers = answers or {}
        self.default = default
        self.calls = []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        answer = self.answers.get(url, self.default)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer(url, **kw)
        if answer is None:
            return _fetched(url)
        return answer


def _context(fetcher=None, adapter=None, source=None, persona=None,
             clock=None, limiter=None):
    from noctornal_api.collection_context import RunContext

    return RunContext(source=source or _source(), run_id=uuid4(),
                      adapter=adapter or Adapter(), route=object(),
                      persona=persona, fetcher=fetcher or Fetcher(),
                      limiter=limiter or Limiter(), clock=clock or Clock())


@pytest.mark.parametrize("url", [
    "https://other.example.test/forums/7/",
    "http://board.example.test/forums/7/",
    "https://board.example.test:8443/forums/7/",
    "https://user@board.example.test/forums/7/",
    "ftp://board.example.test/x",
    "//evil.example.test/steal",
])
def test_another_origin_is_refused_before_anything_is_sent(url):
    from noctornal_api.collection import CollectionError

    fetcher = Fetcher()
    ctx = _context(fetcher)
    with ctx, pytest.raises(CollectionError, match="another site"):
        ctx.fetch(url)
    assert fetcher.calls == []


def test_the_origin_compares_names_after_normalising_them():
    fetcher = Fetcher()
    ctx = _context(fetcher)
    with ctx:
        ctx.fetch("https://BOARD.Example.Test./threads/1/")
    assert len(fetcher.calls) == 1


def test_a_relative_url_resolves_against_the_base():
    fetcher = Fetcher()
    ctx = _context(fetcher)
    with ctx:
        ctx.fetch("../../threads/99/page-2?order=asc")
    assert fetcher.calls[0][0] == "https://board.example.test/threads/99/page-2?order=asc"


def test_the_one_call_is_the_contracts_call():
    from noctornal_api.pinned_http import COLLECTOR_USER_AGENT, REDIRECT_CODES

    fetcher = Fetcher()
    ctx = _context(fetcher)
    with ctx:
        ctx.fetch("threads/1/", accept_status={401, 403})
        entered = ctx.deadline.entered
    _url, kw = fetcher.calls[0]
    assert entered, "the one deadline is entered for the whole fetch"
    assert kw["max_redirects"] == 0
    assert kw["accept_status"] == frozenset({401, 403}) | REDIRECT_CODES
    assert kw["user_agent"] == COLLECTOR_USER_AGENT
    assert kw["deadline"] is ctx.deadline
    assert kw["route"] is ctx.route
    assert kw["max_bytes"] == 1000


def test_a_same_origin_redirect_is_followed_at_most_three_times():
    hop = {}

    def redirect(url, **_kw):
        n = hop.setdefault("n", 0) + 1
        hop["n"] = n
        return _fetched(url, 302, b"", location=f"{BASE}hop{n}?tid={n}")

    fetcher = Fetcher(default=redirect)
    ctx = _context(fetcher)
    with ctx:
        result = ctx.fetch("start")
    assert len(fetcher.calls) == 4, "the first request and three hops"
    assert result.status == 302, "the fourth redirect comes back unfollowed"
    assert fetcher.calls[1][0] == f"{BASE}hop1?tid=1", "the query is kept"


def test_an_off_origin_redirect_is_returned_unfollowed():
    fetcher = Fetcher(default=lambda url, **kw: _fetched(
        url, 302, b"", location="https://login.example.test/sso"))
    ctx = _context(fetcher)
    with ctx:
        result = ctx.fetch("start")
    assert len(fetcher.calls) == 1
    assert result.location == "https://login.example.test/sso"


def test_a_redirect_the_adapter_accepts_is_returned_to_it():
    fetcher = Fetcher(default=lambda url, **kw: _fetched(
        url, 302, b"", location=f"{BASE}login"))
    ctx = _context(fetcher)
    with ctx:
        result = ctx.fetch("start", accept_status={302})
    assert len(fetcher.calls) == 1 and result.status == 302


def test_the_page_budget_is_the_smaller_of_pages_and_rate_times_seconds():
    slow = _context(source=_source(max_rps=0.05),
                    adapter=Adapter(run_seconds=60.0, max_pages=10))
    assert slow.page_budget == 3, "60 seconds at 0.05 per second"
    fast = _context(adapter=Adapter(max_pages=4))
    assert fast.page_budget == 4
    configured = _context(source=_source(parser_config={"page_budget": 2}))
    assert configured.page_budget == 2
    floor = _context(source=_source(max_rps=0.001))
    assert floor.page_budget == 1


def test_the_page_budget_stops_the_walk_before_sending():
    from noctornal_api.collection import BudgetSpent

    fetcher = Fetcher()
    ctx = _context(fetcher, adapter=Adapter(max_pages=2))
    with ctx:
        ctx.fetch("p1")
        ctx.fetch("p2")
        with pytest.raises(BudgetSpent):
            ctx.fetch("p3")
    assert len(fetcher.calls) == 2
    assert any("2 pages" in n for n in ctx.notes())


def test_the_shared_deadline_ends_a_slow_walk():
    from noctornal_api.collection import BudgetSpent

    clock = Clock()

    def slow(url, **_kw):
        clock.now += 25.0
        return _fetched(url)

    fetcher = Fetcher(default=slow)
    ctx = _context(fetcher, clock=clock, adapter=Adapter(run_seconds=60.0))
    pages = 0
    with ctx:
        with pytest.raises(BudgetSpent):
            while True:
                ctx.fetch(f"page-{pages}")
                pages += 1
    assert pages == 3, (
        "25 s pages in a 60 s poll: the fourth is never started, because "
        "the one clock was spent by the pages before it")
    assert clock.now == 1075.0
    assert any("wall clock" in n for n in ctx.notes())


def test_a_deadline_that_runs_out_mid_request_is_budget_spent_and_logged():
    from noctornal_api.collection import BudgetSpent
    from noctornal_api.pinned_http import DeadlineExceeded

    cut = DeadlineExceeded("cut", request_sent=True)
    fetcher = Fetcher(answers={f"{BASE}slow": cut})
    ctx = _context(fetcher)
    with ctx, pytest.raises(BudgetSpent):
        ctx.fetch("slow")
    assert ctx.logged()[0]["status"] is None, "a request that left is logged"


def test_the_byte_budget_stops_the_walk():
    from noctornal_api.collection import BudgetSpent

    fetcher = Fetcher(default=lambda url, **kw: _fetched(url, body=b"x" * 900))
    ctx = _context(fetcher, adapter=Adapter(max_run_bytes=2000))
    with ctx:
        ctx.fetch("a")
        ctx.fetch("b")
        _url, kw = fetcher.calls[-1]
        with pytest.raises(BudgetSpent):
            ctx.fetch("c")
            ctx.fetch("d")
    assert fetcher.calls[2][1]["max_bytes"] == 200, "only what the run has left"


def test_a_page_cut_by_the_run_budget_is_budget_spent_not_a_failure():
    from noctornal_api.collection import BudgetSpent
    from noctornal_api.pinned_http import ResponseTooLarge

    fetcher = Fetcher(answers={
        f"{BASE}a": _fetched(f"{BASE}a", body=b"x" * 900),
        f"{BASE}b": _fetched(f"{BASE}b", body=b"x" * 900),
        f"{BASE}c": ResponseTooLarge("big", max_bytes=200)})
    ctx = _context(fetcher, adapter=Adapter(max_run_bytes=2000))
    with ctx:
        ctx.fetch("a")
        ctx.fetch("b")
        with pytest.raises(BudgetSpent):
            ctx.fetch("c")


def test_a_page_over_its_own_cap_is_a_failure():
    from noctornal_api.collection import BudgetSpent, CollectionError
    from noctornal_api.pinned_http import ResponseTooLarge

    fetcher = Fetcher(default=ResponseTooLarge("big", max_bytes=1000))
    ctx = _context(fetcher)
    with ctx, pytest.raises(CollectionError, match="larger than") as caught:
        ctx.fetch("huge")
    assert not isinstance(caught.value, BudgetSpent)


def test_pace_runs_before_every_request():
    limiter = Limiter()
    fetcher = Fetcher()
    ctx = _context(fetcher, limiter=limiter)
    with ctx:
        ctx.fetch("a")
        ctx.fetch("b")
    assert limiter.calls == [("source", 10.0), ("source", 10.0)]


def test_a_persona_is_paced_by_its_own_gap_too():
    from noctornal_api.collection_context import PersonaContext

    limiter = Limiter()
    persona = PersonaContext(persona_id=uuid4(), handle="h", platform="XENFORO",
                             platform_uid=None, fingerprint={}, authority=None,
                             route=None, lease=None)
    ctx = _context(limiter=limiter, persona=persona)
    with ctx:
        ctx.fetch("a")
    assert limiter.calls == [("source", 10.0), ("persona", 2.0)]


def test_a_429_becomes_rate_limited_with_its_retry_after():
    from noctornal_api.collection import RateLimited
    from noctornal_api.pinned_http import HttpStatusError

    fetcher = Fetcher(default=HttpStatusError(
        429, retry_after=120.0, excerpt="", location=None, location_host=None,
        headers=None))
    ctx = _context(fetcher)
    with ctx, pytest.raises(RateLimited) as caught:
        ctx.fetch("a")
    assert caught.value.retry_after_s == 120.0
    assert ctx.logged()[0]["status"] == 429


def test_a_503_is_rate_limited_only_with_a_retry_after():
    from noctornal_api.collection import RateLimited
    from noctornal_api.pinned_http import HttpStatusError

    def status(retry):
        return HttpStatusError(503, retry_after=retry, excerpt="",
                               location=None, location_host=None, headers=None)

    ctx = _context(Fetcher(default=status(30.0)))
    with ctx, pytest.raises(RateLimited):
        ctx.fetch("a")
    ctx = _context(Fetcher(default=status(None)))
    with ctx, pytest.raises(HttpStatusError):
        ctx.fetch("a")


def test_a_route_refusal_is_egress_unavailable():
    from noctornal_api.collection import EgressUnavailable
    from noctornal_api.pinned_http import DestinationRefused, RouteUnavailable

    for refusal in (RouteUnavailable("no route", code="route_unknown"),
                    DestinationRefused("refused", code="blocked_address")):
        ctx = _context(Fetcher(default=refusal))
        with ctx, pytest.raises(EgressUnavailable):
            ctx.fetch("a")


def test_the_request_log_keeps_the_first_hundred_and_notes_the_rest():
    ctx = _context(adapter=Adapter(max_pages=500, run_seconds=900.0,
                                   max_run_bytes=10 ** 7))
    with ctx:
        for n in range(130):
            ctx.fetch(f"p{n}")
    assert len(ctx.logged()) == 100
    assert any(n.startswith("30 further requests were made") for n in ctx.notes())


def test_request_log_paths_and_queries_are_redacted_and_tokens_stripped():
    from noctornal_api.pinned_http import secret_in_scope

    ctx = _context()
    with ctx, secret_in_scope("hunter2-session-value"):
        ctx.fetch("search?q=hunter2-session-value&_xfToken=1700000000,abcdef&page=2")
        ctx.fetch("x" * 900)
    first = ctx.logged()[0]
    assert "hunter2-session-value" not in first["query"]
    assert "_xfToken=&" in first["query"] and "abcdef" not in first["query"]
    assert len(ctx.logged()[1]["path"]) <= 500
    assert set(first) == {"at", "path", "query", "status", "bytes", "sha256"}


def test_request_log_paths_lose_the_tokens_they_carry():
    """A hostile same-origin Location controls
    the path, and some boards carry the form token in it, as a path
    parameter or as a segment named for the token. Both lose the value;
    an ordinary path keeps every segment."""
    ctx = _context()
    with ctx:
        ctx.fetch("/logout;csrf=abc123secret;view=1")
        ctx.fetch("/index.php/_xfToken/def456secret/next")
        ctx.fetch("/threads/1/page-2;view=flat")
    first, second, third = (e["path"] for e in ctx.logged())
    assert "abc123secret" not in first and first == "/logout;csrf=;view=1"
    assert "def456secret" not in second
    assert second == "/index.php/_xfToken//next"
    assert third == "/threads/1/page-2;view=flat"


def test_record_request_logs_a_non_http_request():
    ctx = _context()
    ctx.record_request(target="messages.getHistory", status=None, nbytes=12,
                       sha256_hex=None)
    assert ctx.logged()[0]["path"] == "messages.getHistory"


def test_a_persona_less_read_sends_the_collector_agent():
    from noctornal_api.pinned_http import COLLECTOR_USER_AGENT

    assert _context().user_agent == COLLECTOR_USER_AGENT


def test_a_persona_http_read_sends_the_persona_agent():
    from noctornal_api.collection_context import PersonaContext

    persona = PersonaContext(persona_id=uuid4(), handle="h", platform="XENFORO",
                             platform_uid=None,
                             fingerprint={"user_agent": "Mozilla/5.0 (X11)"},
                             authority=None, route=None, lease=None)
    ctx = _context(adapter=Adapter(persona_http=True), persona=persona)
    assert ctx.user_agent == "Mozilla/5.0 (X11)"


def test_form_tokens_are_scrubbed_from_raw_markup():
    from noctornal_api.collection_context import _scrub_raw

    html = (b'<form action="/post?_xfToken=1700,deadbeef&x=1">'
            b'<input type="hidden" name="_xfToken" value="1700,deadbeef">'
            b"<input name='my_post_key' value='cafe1234'>"
            b'<input name="csrf_token" value=abc123>'
            b'<div data-csrf="zzz999" class="x">body</div>'
            b'<input name="title" value="keep me">')
    out = _scrub_raw(html)
    for secret in (b"deadbeef", b"cafe1234", b"abc123", b"zzz999"):
        assert secret not in out, secret
    assert b"keep me" in out and b"body" in out


def test_the_scrubber_is_bounded_on_hostile_input():
    import time as _time

    from noctornal_api.collection_context import _scrub_raw

    hostile = (b"<input " + b"name=" * 50000 + b">") * 4 + b"<" * 200000
    started = _time.monotonic()
    _scrub_raw(hostile)
    assert _time.monotonic() - started < 5.0


_MIB = 1 << 20


def _fill(unit: bytes) -> bytes:
    return (unit * (_MIB // len(unit) + 1))[:_MIB]


#: Each shape cost the first scrubber seconds per MiB (b"csrf-" about 6 s,
#: measured 2026-09-25) because its patterns re-scanned a run of name
#: characters from every position inside it. Every one ends in a real
#: token, so no shape takes the fast path that skips a token-free fragment.
_HOSTILE = {
    "a run of token names": _fill(b"csrf-"),
    "a run of name characters": _fill(b"a-") + b' csrf="x"',
    "an input tag of token names": b"<input " + _fill(b"csrf-"),
    "input tags with no end": _fill(b"<input") + b" csrf",
    "an unended tag of token names": _fill(b"<input name=" + b"csrf-" * 20 + b" "),
    "query names of tokens": _fill(b"&" + b"csrf-" * 13),
    "long query names": _fill(b"&" + b"a" * 127) + b"&csrf=1",
    "names at the length cap": _fill(b"a" * 127 + b"=x ") + b"csrf=1",
    "tags full of attributes": _fill(b"<input name=csrf " + b"a=b " * 1000 + b">"),
    "tags full of name attributes": _fill(b"<input " + b"name=" * 800 + b"csrf>"),
    "unclosed quotes": b"csrf " + _fill(b"a='b "),
}


@pytest.mark.parametrize("shape", sorted(_HOSTILE))
def test_the_scrubber_is_linear_on_hostile_input(shape):
    """1 MiB, the most an item may carry, in well under a second, where
    the backtracking version took 6. Generous against a slow runner and
    still twenty times under the old cost."""
    import time as _time

    from noctornal_api.collection_context import _scrub_raw

    started = _time.perf_counter()
    _scrub_raw(_HOSTILE[shape])
    assert _time.perf_counter() - started < 1.0, shape


def test_the_linear_scrubber_still_finds_every_token_shape():
    """The rewrite for linear time keeps every case the first scrubber
    caught, plus a name in brackets and a quoted query, and leaves ordinary
    markup alone."""
    from noctornal_api.collection_context import _scrub_raw

    html = (b'<INPUT TYPE="hidden" NAME="_xfToken" VALUE="tok-1">'
            b'<input value="tok-2" name="data[csrf]">'
            b'<input name=logout_hash value=tok-3>'
            b'<input a="<3" name="xsrf" value="tok-4">'
            b'<span data-XSRF-token=\'tok-5\'>x</span>'
            b'<a href="/p?page=2&amp;my_post_key=tok-6#top">p</a>'
            b'<input name="q" value="keep-1"><inputs name=csrf value="keep-2">'
            b'<a href="/p?topic=csrf-guide">keep-3</a>')
    out = _scrub_raw(html)
    for secret in (b"tok-1", b"tok-2", b"tok-3", b"tok-4", b"tok-5", b"tok-6"):
        assert secret not in out, secret
    for kept in (b"keep-1", b"keep-3", b"page=2", b"topic=csrf-guide"):
        assert kept in out, kept
    assert b"<inputs" in out, "not an input tag, but its csrf attribute value"
    assert _scrub_raw(b"<p>nothing to see</p>") == b"<p>nothing to see</p>"


def _validate(item, adapter=None):
    from noctornal_api.collection import CollectionService, document_categories

    return CollectionService(None)._validate_item(
        item, adapter=adapter or Adapter(), categories=document_categories())


def test_nul_and_lone_surrogates_are_cleaned():
    from noctornal_api.collection import Item

    clean, _naive = _validate(Item(external_id="post:1", title="a\x00b",
                                   body="x\ud800y", author_handle="h\x00"))
    assert clean.title == "a�b"
    assert "\ud800" not in clean.body and clean.body.startswith("x")
    assert clean.author_handle == "h�"


def test_item_validation():
    from datetime import datetime

    from noctornal_api.collection import Item, _ItemInvalid

    with pytest.raises(_ItemInvalid, match="namespaced"):
        _validate(Item(external_id="123"))
    with pytest.raises(_ItemInvalid, match="NUL"):
        _validate(Item(external_id="post:1\x00"))
    with pytest.raises(_ItemInvalid, match="category"):
        _validate(Item(external_id="post:1", category="NOT_A_CATEGORY"))
    with pytest.raises(_ItemInvalid, match="1 MiB"):
        _validate(Item(external_id="post:1", raw_html=b"x" * (1024 * 1024 + 1)))
    clean, naive = _validate(Item(external_id="post:1",
                                  posted_at=datetime(2026, 9, 24, 12, 0)))
    assert naive and clean.posted_at is None, "a naive time is never guessed"
    rss_like = Adapter(requires_authority=False)
    assert _validate(Item(external_id="123"), rss_like)[0].external_id == "123"
