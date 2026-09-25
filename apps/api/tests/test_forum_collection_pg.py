"""The XenForo and MyBB adapters through run_once (F3 and F4,
2026-09-24).

Each test polls a source made of saved fixture pages through the
collection foundation: the refusals before any request, the authority and
exit recorded on the run, posts stored with namespaced ids, their quotes
and signatures cut out and kept beside them, edits versioned, deletions
judged between survivors only, the MyBB times under a declared zone, drift
and login walls and challenges told apart, the per-forum lock, the cursor,
the member profiles and the retention purge. DATABASE_URL-gated; no test
contacts a forum (fixtures through an injected fetcher, and the socket
guard refuses anything but loopback).
"""
from __future__ import annotations

import importlib.util
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

import collection_helpers as h
import forum_helpers as fh

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-fmfc-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_FORUM_ALLOW_DIRECT", "1")
    monkeypatch.delenv("NOCTORNAL_EGRESS_PROXY_URL", raising=False)
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _world(conn, *, kind="XENFORO", parser="xenforo", base_url=fh.XF_THREAD,
           config=None, max_rps=999):
    """Two people, an exit, a forum source and a confirmed persona-less
    authority over it."""
    from psycopg.types.json import Jsonb

    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    egress = h.egress_profile(conn, P)
    source = h.source(conn, P, kind=kind, parser=parser, base_url=base_url,
                      egress=egress, max_rps=max_rps)
    if config:
        conn.execute("UPDATE collect.source SET parser_config = %s WHERE id = %s",
                     (Jsonb(config), source))
    view = h.authority(conn, recorder=recorder, confirmer=confirmer,
                       source_ids=[source], adapters=fh.registry())
    return {"recorder": recorder, "egress": egress, "source": source,
            "authority": view}


def _svc(conn, site, registry=None, raw_store="memory"):
    from noctornal_api.collection import CollectionService
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    store = InMemoryDocumentRawStorage() if raw_store == "memory" else raw_store
    return CollectionService(conn, registry or fh.registry(), fetcher=site,
                             raw_store=store, sleep=lambda _s: None)


def _docs(conn, source):
    return conn.execute(
        """SELECT external_id, version, author_handle, author_uid, thread_ref,
                  parent_ref, category, body_text, posted_at, title,
                  is_deleted_upstream, body_html_key, id, supersedes_id
             FROM collect.document WHERE source_id = %s
            ORDER BY external_id, version""", (source,)).fetchall()


def _latest(conn, source, external_id):
    return conn.execute(
        """SELECT id, version, body_text, is_deleted_upstream, supersedes_id
             FROM collect.document WHERE source_id = %s AND external_id = %s
            ORDER BY version DESC LIMIT 1""", (source, external_id)).fetchone()


def _run(conn, run_id):
    return conn.execute(
        """SELECT status::text, error_class, error_detail, authority_id,
                  egress_profile_id, cursor, notes, requests, items_deleted
             FROM collect.collection_run WHERE id = %s""", (run_id,)).fetchone()


# --- a thread, end to end -----------------------------------------------

def test_a_public_thread_lands_as_posts_with_their_side_rows(conn):
    w = _world(conn)
    site = fh.xf_thread_site()
    result = _svc(conn, site).run_once(w["source"], actor_id=w["recorder"])
    assert result.status == "OK", (result.error, result.warnings)
    run = _run(conn, result.run_id)
    assert str(run[3]) == w["authority"]["id"], "the run records its authority"
    assert run[4] == w["egress"], "and the source's own exit"
    # Page 1, then the newest page (3), then backwards within the window.
    assert site.urls() == [fh.XF_THREAD, f"{fh.XF_THREAD}page-3",
                           f"{fh.XF_THREAD}page-2"]
    for _url, kw in site.calls:
        assert kw["user_agent"] == "NocTORnal-collector/1"
        assert kw["max_redirects"] == 0
    docs = {d[0]: d for d in _docs(conn, w["source"])}
    assert set(docs) == {"post:1001", "post:1002", "post:1003", "post:1021",
                         "post:1022", "post:1023", "post:1041", "post:1042",
                         "post:1043"}
    first = docs["post:1001"]
    assert first[2] == "carder_kid" and first[3] == "member:42"
    assert first[4] == "thread:1234" and first[5] == "post:999"
    assert first[6] == "FORUM_POST"
    assert first[9] == "[WTS] Fresh dumps, track 1+2", "the opening post carries the title"
    assert docs["post:1002"][9] is None
    assert first[8] == datetime(2026, 9, 8, 8, 15, tzinfo=timezone.utc)
    assert "own@xmpp.example.test" in first[7]
    assert "quoted@xmpp.example.test" not in first[7], "a quote is not the quoter's"
    assert "sig@xmpp.example.test" not in first[7], "a signature is not the post"
    assert "5 &lt; 10" in first[7], "entities are decoded exactly once"
    assert docs["post:1003"][3] is None, "a guest has no member id"
    side = conn.execute(
        """SELECT signature_text, quoted_post_refs, reactions
             FROM collect.forum_post WHERE document_id = %s""", (first[12],)).fetchone()
    assert side[0] == "Jabber: sig@xmpp.example.test | escrow only"
    assert side[1] == ["post:999"]
    vouch = conn.execute("SELECT reactions FROM collect.forum_post WHERE document_id = %s",
                         (docs["post:1002"][12],)).fetchone()[0]
    assert vouch == {"count": 5, "reactors": ["Alice", "Bob"], "types": ["Like"]}
    assert all(d[11] for d in docs.values()), "each post keeps its own fragment"
    cursor = run[5]
    assert cursor["t"]["1234"]["p"] == 3
    assert len(run[7]) == 3, "three requests in the custody log"


def test_the_stored_fragment_is_the_post_alone_with_no_token(conn):
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    w = _world(conn)
    store = InMemoryDocumentRawStorage()
    _svc(conn, fh.xf_thread_site(), raw_store=store).run_once(
        w["source"], actor_id=None)
    key = conn.execute(
        "SELECT body_html_key FROM collect.document WHERE source_id = %s "
        "AND external_id = 'post:1002'", (w["source"],)).fetchone()[0]
    raw = store.get(key)
    assert raw.startswith(b"<article") and b'data-content="post-1002"' in raw
    assert b"post-1001" not in raw, "one post, never the page"
    assert b"9f0e3c1b2a7d6e5f4a3b2c1d0e9f8a7b" not in raw, "no form token survives"
    assert b"<input" not in raw and b"<form" not in raw


def test_a_second_poll_versions_an_edit_and_flags_a_deletion_between_survivors(conn):
    w = _world(conn)
    _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)
    later = fh.xf_thread_site(**{f"{fh.XF_THREAD}page-3": "xenforo/thread_page3_later.html"})
    result = _svc(conn, later).run_once(w["source"], actor_id=None)
    assert result.status == "OK", result.warnings
    # The window: from recheck_pages (2) before the last page read.
    assert later.urls() == [fh.XF_THREAD, f"{fh.XF_THREAD}page-2",
                            f"{fh.XF_THREAD}page-3"]
    edited = _latest(conn, w["source"], "post:1041")
    assert edited[1] == 2 and "sold out" in edited[2] and edited[4] is not None
    gone = _latest(conn, w["source"], "post:1042")
    assert gone[3] is True, "1042 vanished between 1041 and 1043, both still there"
    assert result.items_deleted == 1
    assert _latest(conn, w["source"], "post:1044") is not None
    assert _latest(conn, w["source"], "post:1043")[3] is False


def test_a_post_that_only_moved_off_the_pages_read_is_not_called_deleted(conn):
    """A moderator removed an earlier post, so the first post of the window
    moved to a page this poll does not read. Nothing between two survivors
    is missing, so nothing is flagged."""
    w = _world(conn, config={"recheck_pages": 0})
    _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)
    # Page 3 now opens with 1042: 1041 moved back to page 2, which this
    # poll (recheck_pages 0) does not read; a new post 1044 closes it.
    shifted = fh.page("xenforo/thread_page3.html").replace(
        b'data-content="post-1041"', b'data-content="post-1044"')
    result = _svc(conn, fh.xf_thread_site(**{f"{fh.XF_THREAD}page-3": (200, shifted)})
                  ).run_once(w["source"], actor_id=None)
    assert result.items_deleted == 0
    assert _latest(conn, w["source"], "post:1041")[3] is False


def test_a_rechecked_unchanged_post_raises_no_second_watch_hit(conn):
    from datetime import date

    from noctornal_api.cases import CaseService

    w = _world(conn)
    case_owner, _ = h.user(conn, P, roles=("CASE_OWNER",))
    case = CaseService(conn).create(
        code=f"OP-FMW-{uuid4().hex[:6]}", title="forum watch",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=case_owner, created_by=case_owner)
    conn.execute(
        """INSERT INTO collect.watch (case_id, source_id, name, target_kind,
                                      target_ref, keywords, owner_user_id,
                                      suppress_window_s)
           VALUES (%s, %s, 'jabber', 'THREAD', 'thread:1234',
                   ARRAY['own@xmpp.example.test'], %s, 0)""",
        (case, w["source"], case_owner))
    first = _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)
    conn.execute("UPDATE collect.source SET next_due_at = now() WHERE id = %s",
                 (w["source"],))
    again = _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)
    assert first.watch_hits == 1 and again.watch_hits == 0


# --- what is refused, and when --------------------------------------------

def test_with_no_proxy_and_no_override_the_source_is_held_and_nothing_is_sent(conn, monkeypatch):
    from noctornal_api.collection import CollectionService, SourceRefused

    w = _world(conn)
    monkeypatch.delenv("NOCTORNAL_FORUM_ALLOW_DIRECT")
    site = fh.xf_thread_site()
    svc = _svc(conn, site)
    with pytest.raises(SourceRefused, match="own address"):
        svc.run_once(w["source"], actor_id=None)
    assert site.calls == []
    assert conn.execute("SELECT count(*) FROM collect.collection_run WHERE source_id = %s",
                        (w["source"],)).fetchone()[0] == 0
    held = CollectionService(conn, fh.registry()).held_sources(clearance="RED")
    assert any(x["id"] == w["source"] and x["reason"] == "REFUSED" for x in held)


def test_no_ceiling_declared_means_no_run_row_and_no_request(conn, monkeypatch):
    from noctornal_api.collection import SourceRefused

    w = _world(conn)
    monkeypatch.delenv("NOCTORNAL_FORUM_SOURCE_CEILING")
    site = fh.xf_thread_site()
    with pytest.raises(SourceRefused, match="not declared"):
        _svc(conn, site).run_once(w["source"], actor_id=None)
    assert site.calls == []


def test_an_over_ceiling_source_with_no_ceiling_declared_is_the_plain_404(conn, monkeypatch):
    from noctornal_api.collection import CollectionNotFound

    w = _world(conn)
    monkeypatch.delenv("NOCTORNAL_FORUM_SOURCE_CEILING")
    with pytest.raises(CollectionNotFound):
        _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None,
                                                 clearance="GREEN")


def test_no_confirmed_authority_is_a_blocked_run_with_no_request(conn):
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    egress = h.egress_profile(conn, P)
    source = h.source(conn, P, parser="xenforo", base_url=fh.XF_THREAD, egress=egress)
    site = fh.xf_thread_site()
    result = _svc(conn, site).run_once(source, actor_id=recorder)
    assert result.status == "BLOCKED"
    assert _run(conn, result.run_id)[1] == "AuthorityMissing"
    assert site.calls == []


def test_a_persona_bound_forum_source_is_refused(conn):
    from noctornal_api.collection import SourceRefused

    w = _world(conn)
    persona = h.persona(conn, P, platform="XENFORO")
    conn.execute("UPDATE collect.source SET collection_account_id = %s, "
                 "egress_profile_id = NULL WHERE id = %s", (persona, w["source"]))
    with pytest.raises(SourceRefused, match="reads without one"):
        _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)


def test_an_address_that_is_neither_thread_nor_board_is_refused(conn):
    from noctornal_api.collection import SourceRefused

    w = _world(conn, base_url=f"{fh.XF_BASE}/members/carder_kid.42/")
    with pytest.raises(SourceRefused, match="neither a XenForo thread nor a board"):
        _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)


# --- outcomes told apart --------------------------------------------------

def test_a_login_wall_fails_the_run_as_a_login_wall_and_stores_nothing(conn):
    w = _world(conn)
    site = fh.Site({fh.XF_THREAD: (403, "xenforo/login.html")})
    result = _svc(conn, site).run_once(w["source"], actor_id=None)
    run = _run(conn, result.run_id)
    assert result.status == "FAILED" and run[1] == "LoginWall"
    assert _docs(conn, w["source"]) == []
    assert len(run[7]) == 1, "the request is in the custody log all the same"


def test_a_redirect_to_the_sign_in_page_is_a_login_wall(conn):
    w = _world(conn)
    site = fh.Site({fh.XF_THREAD: lambda url, **kw: fh.fetched(
        url, 303, location=f"{fh.XF_BASE}/login/")})
    # A same-origin redirect is followed by RunContext; the login page it
    # lands on is what the adapter sees.
    site.pages[f"{fh.XF_BASE}/login/"] = (200, "xenforo/login.html")
    result = _svc(conn, site).run_once(w["source"], actor_id=None)
    assert _run(conn, result.run_id)[1] == "LoginWall"


def test_a_challenge_page_is_blocked_not_drift_and_the_next_poll_waits_longer(conn):
    w = _world(conn)
    site = fh.Site({fh.XF_THREAD: (503, "xenforo/challenge.html")})
    result = _svc(conn, site).run_once(w["source"], actor_id=None)
    run = _run(conn, result.run_id)
    assert result.status == "BLOCKED" and run[1] == "SourceBlocked"
    assert "anti-bot challenge" in run[2]
    health, failures, due = conn.execute(
        "SELECT health, consecutive_failures, next_due_at FROM collect.source "
        "WHERE id = %s", (w["source"],)).fetchone()
    assert failures == 0 and health in ("OK", "UNKNOWN"), (
        "a challenge is not parser ill health")
    # poll_interval_s 300 (the helper's): twice it after one challenge.
    assert due >= datetime.now(timezone.utc) + timedelta(seconds=590)
    _svc(conn, site).run_once(w["source"], actor_id=None)
    due2 = conn.execute("SELECT next_due_at FROM collect.source WHERE id = %s",
                        (w["source"],)).fetchone()[0]
    assert due2 >= datetime.now(timezone.utc) + timedelta(seconds=1190), "the ladder climbs"


def test_a_429_is_rate_limited(conn):
    from noctornal_api.pinned_http import HttpStatusError

    w = _world(conn)
    site = fh.Site({fh.XF_THREAD: HttpStatusError(
        429, retry_after=120.0, excerpt="", location=None, location_host=None,
        headers=None)})
    result = _svc(conn, site).run_once(w["source"], actor_id=None)
    assert result.status == "RATE_LIMITED"
    due = conn.execute("SELECT next_due_at FROM collect.source WHERE id = %s",
                       (w["source"],)).fetchone()[0]
    assert due >= datetime.now(timezone.utc) + timedelta(seconds=120)


def test_two_drifting_polls_leave_the_source_degraded_and_hold_the_cursor(conn):
    from noctornal_api.collection import CollectionService

    w = _world(conn)
    _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)
    before = conn.execute(
        "SELECT cursor FROM collect.collection_run WHERE source_id = %s "
        "ORDER BY started_at DESC LIMIT 1", (w["source"],)).fetchone()[0]
    restyled = fh.xf_thread_site(**{fh.XF_THREAD: "xenforo/thread_restyled.html",
                                    f"{fh.XF_THREAD}page-2": "xenforo/thread_restyled.html",
                                    f"{fh.XF_THREAD}page-3": "xenforo/thread_restyled.html"})
    for _ in range(2):
        result = _svc(conn, restyled).run_once(w["source"], actor_id=None)
        assert result.status == "PARTIAL"
        assert _run(conn, result.run_id)[1] == "ParserDrift"
    health = conn.execute("SELECT health FROM collect.source WHERE id = %s",
                          (w["source"],)).fetchone()[0]
    assert health == "DEGRADED"
    assert any(s["id"] == str(w["source"])
               for s in CollectionService(conn).unhealthy_sources(clearance="RED"))
    after = conn.execute(
        "SELECT cursor FROM collect.collection_run WHERE source_id = %s "
        "ORDER BY started_at DESC LIMIT 1", (w["source"],)).fetchone()[0]
    assert after == before, "a drifting run never moves the reading position"


def test_the_walk_stops_at_its_page_budget_and_resumes_from_there(conn):
    w = _world(conn, config={"page_budget": 1})
    site = fh.xf_thread_site()
    result = _svc(conn, site).run_once(w["source"], actor_id=None)
    assert result.status == "OK" and site.urls() == [fh.XF_THREAD]
    assert any("stopped at its budget" in n for n in result.notes)
    assert _run(conn, result.run_id)[5]["t"]["1234"]["p"] == 1


# --- MyBB -----------------------------------------------------------------

def _mybb(conn, config=None):
    return _world(conn, kind="MYBB", parser="mybb", base_url=fh.MB_THREAD,
                  config=fh.MB_CONFIG if config is None else config)


def test_a_mybb_thread_is_read_in_linear_mode_with_times_in_the_declared_zone(conn):
    w = _mybb(conn)
    site = fh.mb_thread_site()
    result = _svc(conn, site).run_once(w["source"], actor_id=None)
    assert result.status == "OK", result.warnings
    assert all("mode=linear" in u for u in site.urls())
    docs = {d[0]: d for d in _docs(conn, w["source"])}
    assert docs["post:120"][3] == "member:7" and docs["post:120"][5] == "post:99"
    assert "quoted@xmpp.example.test" not in docs["post:120"][7]
    # 'Today, 04:12 PM' titled 09-10-2026, in Riga's summer time (UTC+3).
    assert docs["post:121"][8] == datetime(2026, 9, 10, 13, 12, tzinfo=timezone.utc)
    # '5 Minutes Ago' titled with the whole date and time.
    assert docs["post:122"][8] == datetime(2026, 9, 10, 14, 40, tzinfo=timezone.utc)


def test_a_mybb_source_without_its_zone_and_formats_is_refused(conn):
    from noctornal_api.collection import SourceRefused

    w = _mybb(conn, config={"page_budget": 3})
    with pytest.raises(SourceRefused, match="time zone, date format and time format"):
        _svc(conn, fh.mb_thread_site()).run_once(w["source"], actor_id=None)


def test_mybb_times_that_do_not_read_are_a_gap_not_drift(conn):
    """Declared as d-m-Y while the board prints m-d-Y and a 24 hour clock:
    every time is refused. The posts are stored with no posting time, the
    run says so in a note, and health and the cursor move on."""
    w = _mybb(conn, config={**fh.MB_CONFIG, "time_format": "H:i"})
    result = _svc(conn, fh.mb_thread_site()).run_once(w["source"], actor_id=None)
    assert result.status == "OK"
    assert any("posting time was not stored" in n for n in result.notes)
    assert all(d[8] is None for d in _docs(conn, w["source"]))
    assert _run(conn, result.run_id)[5]["t"]["12"]["p"] == 2


# --- boards and members ---------------------------------------------------

def test_a_board_is_walked_most_recently_active_thread_first(conn):
    w = _world(conn, base_url=fh.XF_BOARD, config={"page_budget": 3,
                                                   "recheck_pages": 0})
    site = fh.xf_thread_site(**{fh.XF_BOARD: "xenforo/board.html"})
    result = _svc(conn, site).run_once(w["source"], actor_id=None)
    assert result.status == "OK", result.warnings
    # The board, then thread 1234 (active 2026-09-10) page 1 and its newest
    # page; the budget ends before 1235 and the sticky rules thread.
    assert site.urls() == [fh.XF_BOARD, fh.XF_THREAD, f"{fh.XF_THREAD}page-3"]
    assert "wtb-drops-eu" not in " ".join(site.urls())


def test_member_pages_are_read_when_asked_and_filed_by_their_own_id(conn):
    w = _world(conn, config={"member_pages": 1, "page_budget": 3,
                             "recheck_pages": 0})
    # A one-page thread, so the budget reaches the member phase.
    single = fh.page("xenforo/thread_page1.html").replace(
        b'<li class="pageNav-page', b'<li class="x')
    site = fh.Site({fh.XF_THREAD: (200, single),
                    f"{fh.XF_BASE}/members/42/about": "xenforo/member_42.html"})
    result = _svc(conn, site).run_once(w["source"], actor_id=None)
    assert result.status == "OK", result.warnings
    assert site.urls() == [fh.XF_THREAD, f"{fh.XF_BASE}/members/42/about"]
    member = conn.execute(
        """SELECT d.category, d.author_uid, d.body_text, m.profile
             FROM collect.document d JOIN collect.forum_member m ON m.document_id = d.id
            WHERE d.source_id = %s AND d.external_id = 'member:42'""",
        (w["source"],)).fetchone()
    assert member is not None
    assert member[0] == "FORUM_MEMBER" and member[1] == "member:42"
    assert "own@xmpp.example.test" in member[2]
    assert "312" not in member[2], "a counter is not what a version is judged on"
    assert member[3]["fields"]["Messages"] == "312"
    from noctornal_api.forum_adapters import forum_details
    doc = _latest(conn, w["source"], "member:42")[0]
    shown = forum_details(conn, doc, clearance="AMBER")
    assert shown["kind"] == "member" and shown["profile"]["title"] == "Trusted seller"


# --- one forum at a time ----------------------------------------------------

def test_a_second_source_on_the_same_forum_waits_its_turn(conn):
    from noctornal_api.db import connect

    w = _world(conn)
    other = connect()
    try:
        other.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                      (f"collect.forum_host:{fh.XF_BASE}",))
        site = fh.xf_thread_site()
        result = _svc(conn, site).run_once(w["source"], actor_id=None)
        assert result.status == "BLOCKED" and "Another source on this forum" in result.blocked_reason
        assert site.calls == []
    finally:
        other.close()
    # Released at the end of every poll: the next one runs.
    assert _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None).status == "OK"


# --- side rows: read back under the labels, and purged ----------------------

def test_the_side_rows_are_read_only_under_the_document_and_source_labels(conn):
    from noctornal_api.collection import CollectionNotFound
    from noctornal_api.forum_adapters import forum_details

    w = _world(conn)
    _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)
    doc = _latest(conn, w["source"], "post:1001")[0]
    got = forum_details(conn, doc, clearance="AMBER")
    assert got["signature_text"] == "Jabber: sig@xmpp.example.test | escrow only"
    assert got["quoted_post_refs"] == ["post:999"]
    with pytest.raises(CollectionNotFound):
        forum_details(conn, doc, clearance="GREEN")
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                 (w["source"],))
    with pytest.raises(CollectionNotFound):
        forum_details(conn, doc, clearance="AMBER")
    with pytest.raises(CollectionNotFound):
        forum_details(conn, uuid4(), clearance="RED")


def test_the_purge_deletes_the_side_rows_and_a_held_case_keeps_them(conn):
    """The purge empties a forum post and deletes its side row; a post
    cited by a case under legal hold is kept whole, side row included
    (docs/00 decision 74)."""
    from datetime import date

    from noctornal_api.cases import CaseService
    from noctornal_api.rawstore import InMemoryDocumentRawStorage
    from noctornal_api.retention import RetentionService

    w = _world(conn)
    store = InMemoryDocumentRawStorage()
    _svc(conn, fh.xf_thread_site(), raw_store=store).run_once(w["source"], actor_id=None)
    owner, _ = h.user(conn, P, roles=("CASE_OWNER",))
    case = CaseService(conn).create(
        code=f"OP-FMH-{uuid4().hex[:6]}", title="forum hold",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)
    conn.execute('UPDATE core."case" SET legal_hold = true, legal_hold_reason = %s '
                 'WHERE id = %s', ("court order 2026-91", case))
    held = _latest(conn, w["source"], "post:1001")[0]
    loose = _latest(conn, w["source"], "post:1002")[0]
    conn.execute("""INSERT INTO collect.proposal
                        (case_id, kind, payload, origin, rationale, document_id)
                    VALUES (%s, 'NODE', '{}', 'forum', 'a reason', %s)""", (case, held))
    conn.execute("UPDATE collect.document SET retain_until = now() - interval '1 day' "
                 "WHERE id = ANY(%s)", ([held, loose],))
    RetentionService(conn, document_raw=store).purge_due(
        actor_id=owner, authority="retention schedule", dry_run=False)
    purged = conn.execute("SELECT purged_at IS NOT NULL, author_uid FROM collect.document "
                          "WHERE id = %s", (loose,)).fetchone()
    assert purged == (True, None)
    assert conn.execute("SELECT count(*) FROM collect.forum_post WHERE document_id = %s",
                        (loose,)).fetchone()[0] == 0
    assert conn.execute("SELECT purged_at FROM collect.document WHERE id = %s",
                        (held,)).fetchone()[0] is None
    assert conn.execute("SELECT signature_text FROM collect.forum_post WHERE document_id = %s",
                        (held,)).fetchone()[0].startswith("Jabber")


def test_forum_documents_have_no_clock_until_a_rule_exists_and_the_run_says_so(conn):
    w = _world(conn)
    result = _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)
    assert any("No retention rule covers FORUM_POST" in n for n in result.notes)
    assert conn.execute("SELECT count(*) FROM collect.document WHERE source_id = %s "
                        "AND retain_until IS NOT NULL", (w["source"],)).fetchone()[0] == 0


# --- the bounded parser, through run_once -------------------------------------

def test_the_real_poll_parses_each_page_in_the_bounded_child(conn):
    from noctornal_api.collection import RssAdapter
    from noctornal_api.forum_adapters import XenForoAdapter

    w = _world(conn, config={"page_budget": 1})
    registry = {"rss": RssAdapter(), "xenforo": XenForoAdapter(sleep=lambda _s: None)}
    result = _svc(conn, fh.xf_thread_site(), registry=registry).run_once(
        w["source"], actor_id=None)
    assert result.status == "OK" and result.items_new == 3


# --- the migration --------------------------------------------------------------

def test_the_downgrade_refuses_while_side_rows_exist(conn):
    import psycopg

    w = _world(conn)
    _svc(conn, fh.xf_thread_site()).run_once(w["source"], actor_id=None)
    path = (Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
            / "0104_forum_post_and_member.py")
    spec = importlib.util.spec_from_file_location("mig0104", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    with pytest.raises(psycopg.errors.RaiseException, match="refusing to downgrade 0104"):
        with conn.transaction():
            module.downgrade()
    assert conn.execute("SELECT to_regclass('collect.forum_post')").fetchone()[0]
