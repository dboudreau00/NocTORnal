"""collection-watch-regex-redos (review of 2026-10-03).

A watch's regexes ran with `re.search` over the collected document's text
(written by the people under investigation, up to 200,000 characters of a
forum post), inside the persist transaction with the source's poll lock
held, with no bound: a pattern with a nested repeat (`(a+)+$`) does not
raise `re.error`, it spins, so one such pattern wedged a source's poll, its
transaction and its lock.

The regex is now matched in a child process under a wall clock the
collector enforces, before the transaction opens, and a pattern that does
not finish is reported once per run. These tests never let the hostile
pattern run in THIS process: on dc28ffa the patched `re.search` raises where
the old code called it, so the old code fails fast instead of hanging.

Prefix `r46w2-`. DATABASE_URL-gated.
"""
from __future__ import annotations

import os
import re
import sys
import time
from datetime import date
from uuid import uuid4

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "r46w2-"
HOSTILE = "(a+)+$"
CRAFTED = "a" * 48 + "!"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _watch(conn, source, owner, **cols):
    from noctornal_api.cases import CaseService

    case = CaseService(conn).create(
        code=f"OP-R46W-{uuid4().hex[:6]}", title="regex bound", legal_basis="order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner)
    columns = {"keywords": None, "regexes": None, **cols}
    return conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref, keywords,
                regexes, owner_user_id, suppress_window_s)
           VALUES (%s, %s, 'r46 watch', 'FORUM', 'b', %s, %s, %s, 0)
           RETURNING id""",
        (case, source, columns["keywords"], columns["regexes"], owner)).fetchone()[0]


def _poll(conn, owner, *items, regexes=None, keywords=None):
    from noctornal_api.collection import CollectionService, FetchResult

    source = h.source(conn, P, kind="RSS", parser="rss", egress=None)
    watch = _watch(conn, source, owner, regexes=regexes, keywords=keywords)

    class Stub:
        key, version = "rss", "test"

        def fetch(self, **kw):
            return FetchResult(items=list(items), http_status=200)

    result = CollectionService(conn, {"rss": Stub()}).run_once(source, actor_id=None)
    return result, watch


def _hits(conn, watch):
    return [m for (m,) in conn.execute(
        "SELECT matched_on::text FROM collect.watch_hit WHERE watch_id = %s", (watch,))]


@pytest.fixture
def owner(conn):
    return h.user(conn, P, roles=("COLLECTOR",))[0]


@pytest.fixture
def no_regex_in_process(monkeypatch):
    """The parent must never run a watch pattern itself."""
    real = re.search

    def guarded(pattern, string, flags=0):
        if isinstance(pattern, str) and pattern == HOSTILE:
            raise AssertionError("a watch regex was matched in the API process")
        return real(pattern, string, flags)

    monkeypatch.setattr(re, "search", guarded)


pg = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")


@pg
def test_a_catastrophic_pattern_is_stopped_reported_and_the_poll_finishes(
        conn, owner, monkeypatch, no_regex_in_process):
    from noctornal_api import watch_regex
    from noctornal_api.collection import Item

    monkeypatch.setattr(watch_regex, "PATTERN_WALL_S", 2.0)
    began = time.monotonic()
    result, watch = _poll(conn, owner, Item(external_id="post:1", body=CRAFTED),
                          regexes=[HOSTILE])
    assert time.monotonic() - began < 60, "the poll was not bounded"
    assert result.status == "PARTIAL"
    assert len(result.warnings) == 1 and "was stopped" in result.warnings[0]
    assert "did not finish within its time limit" in result.warnings[0]
    assert HOSTILE in result.warnings[0]
    assert _hits(conn, watch) == []
    status, error_class = conn.execute(
        "SELECT status::text, error_class FROM collect.collection_run WHERE id = %s",
        (result.run_id,)).fetchone()
    assert (status, error_class) == ("PARTIAL", "WatchPatternError")


@pg
def test_one_stopped_pattern_does_not_silence_the_other_watches_or_patterns(
        conn, owner, monkeypatch, no_regex_in_process):
    from noctornal_api import watch_regex
    from noctornal_api.collection import Item

    monkeypatch.setattr(watch_regex, "PATTERN_WALL_S", 2.0)
    result, watch = _poll(conn, owner,
                          Item(external_id="post:1", title="Selling", body=CRAFTED),
                          regexes=[HOSTILE, r"sell[a-z]+"], keywords=["selling"])
    assert result.status == "PARTIAL"
    matched = _hits(conn, watch)
    assert len(matched) == 1
    assert "keyword:selling" in matched[0] and "regex:sell[a-z]+" in matched[0]
    assert HOSTILE not in matched[0]


@pg
def test_the_regex_is_matched_before_the_persist_transaction_opens(
        conn, owner, monkeypatch):
    """The state of the connection when the bounded matcher is asked: no
    transaction, so a pattern being stopped holds no row lock."""
    import psycopg

    from noctornal_api import watch_regex
    from noctornal_api.collection import Item

    seen = []
    real = watch_regex.run

    def run(jobs, **kw):
        seen.append(conn.info.transaction_status)
        return real(jobs, **kw)

    monkeypatch.setattr(watch_regex, "run", run)
    result, _watch_id = _poll(conn, owner, Item(external_id="post:1", body="hello"),
                              regexes=[r"hel+o"])
    assert result.watch_hits == 1
    assert seen and all(state == psycopg.pq.TransactionStatus.IDLE for state in seen), seen


@pg
def test_a_pattern_that_matches_still_raises_its_hit_with_its_reason(conn, owner):
    from noctornal_api.collection import Item

    result, watch = _poll(conn, owner,
                          Item(external_id="post:1", title="T", body="Contact me at"
                               " Seller.Handle@jabber.example.test today",
                               meta={"forum": {"signature": "ICQ 123456789 BlackMarket"}}),
                          regexes=[r"seller\.handle@jabber\.example\.test", r"icq \d{9}",
                                   r"never-present-\d+"])
    assert result.status == "OK" and result.watch_hits == 1
    (matched,) = _hits(conn, watch)
    assert "regex:seller\\\\.handle@jabber\\\\.example\\\\.test" in matched
    assert "signature_regex:icq \\\\d{9}" in matched
    assert "never-present" not in matched


@pg
def test_a_pattern_that_will_not_compile_is_still_reported_once_in_the_old_words(
        conn, owner, no_regex_in_process):
    from noctornal_api.collection import Item

    result, watch = _poll(conn, owner,
                          Item(external_id="post:1", body="one"),
                          Item(external_id="post:2", body="two"),
                          regexes=["[unclosed"])
    assert result.status == "PARTIAL"
    assert sum("will not compile" in text for text in result.warnings) == 1
    assert "[unclosed" in result.warnings[0] and _hits(conn, watch) == []


# --- the bounded matcher itself: no database -------------------------------

def test_the_matcher_answers_each_text_and_classifies_each_failure():
    from noctornal_api import watch_regex

    verdicts = watch_regex.run({
        "ok+": ["xxokkxx", "nothing"], "[unclosed": ["x"], HOSTILE: [CRAFTED], "none": []},
        wall_s=1.5)
    assert verdicts.hits == {("ok+", "xxokkxx"): True, ("ok+", "nothing"): False}
    assert verdicts.failed["[unclosed"][0] == watch_regex.COMPILE
    assert "unterminated" in verdicts.failed["[unclosed"][1]
    assert verdicts.failed[HOSTILE][0] == watch_regex.LIMIT
    assert "time limit" in verdicts.failed[HOSTILE][1]
    assert "none" not in verdicts.failed and not any(k[0] == HOSTILE for k in verdicts.hits)


def test_a_pattern_that_fails_part_way_keeps_none_of_its_verdicts(monkeypatch):
    """Half an answer would fire the watch on some posts and not others."""
    from noctornal_api import watch_regex

    monkeypatch.setattr(watch_regex, "BATCH_BYTES", 400)
    texts = ["fine " + "x" * 50] * 3 + [CRAFTED] + ["after"] * 3
    verdicts = watch_regex.run({HOSTILE: texts}, wall_s=1.5)
    assert HOSTILE in verdicts.failed
    assert not any(key[0] == HOSTILE for key in verdicts.hits)


def test_the_run_budget_stops_further_patterns_and_says_so(monkeypatch):
    from noctornal_api import watch_regex

    verdicts = watch_regex.run({"a": ["a"], "b": ["b"]}, wall_s=1.0, budget_s=0.0)
    assert set(verdicts.failed) == {"a", "b"}
    assert all(kind == watch_regex.LIMIT and "time for watch patterns" in text
               for kind, text in verdicts.failed.values())


def test_a_child_that_never_answers_is_killed_at_the_limit(tmp_path):
    from noctornal_api import watch_regex

    silent = tmp_path / "g46s_silent_child.py"
    silent.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    began = time.monotonic()
    verdicts = watch_regex.run({"a": ["a"]}, wall_s=0.8, argv=[sys.executable, str(silent)])
    assert time.monotonic() - began < 20
    assert verdicts.failed["a"][0] == watch_regex.LIMIT
    assert "time limit" in verdicts.failed["a"][1]


def test_a_child_that_answers_nonsense_is_a_failure_not_a_verdict(tmp_path):
    from noctornal_api import watch_regex

    liar = tmp_path / "g46s_liar_child.py"
    liar.write_text("import sys\nsys.stdin.buffer.read()\n"
                    "sys.stdout.write('{\"ok\": true, \"hits\": [true, true, true]}')\n",
                    encoding="utf-8")
    verdicts = watch_regex.run({"a": ["a"]}, wall_s=5, argv=[sys.executable, str(liar)])
    assert verdicts.failed["a"][0] == watch_regex.LIMIT and not verdicts.hits


def test_a_text_with_a_lone_surrogate_or_non_ascii_reaches_the_matcher():
    from noctornal_api import watch_regex

    texts = ["café 😀 ok", "lone \ud800 surrogate ok", "привет"]
    verdicts = watch_regex.run({"ok$": texts, "при": texts}, wall_s=10)
    assert verdicts.hits[("ok$", texts[0])] and verdicts.hits[("ok$", texts[1])]
    assert not verdicts.hits[("ok$", texts[2])]
    assert verdicts.hits[("при", texts[2])]


def test_the_watch_text_is_one_function_for_the_verdicts_and_the_matching():
    from noctornal_api.collection import Item, _watch_texts

    item = Item(external_id="p", title="Hello", body="World",
                meta={"forum": {"signature": "SIG Line"}})
    assert _watch_texts(item) == ("hello\nworld", "sig line")
    assert _watch_texts(Item(external_id="p", body="b")) == ("\nb", "")
