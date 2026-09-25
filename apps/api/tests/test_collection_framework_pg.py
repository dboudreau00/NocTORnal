"""The collection framework end to end (2026-09-24).

run_once around an adapter: the refusals before any lock or run row, the
cursor round trip, the run row's start, requester and exit, raw markup per
item, the identity fields, drift, login walls, deletions, the request log
on every outcome, per-item savepoints, BLOCKED and RATE_LIMITED, the held
list, and RSS polled exactly as before, through the passive route.

No test touches the network: authority adapters are stubs (collection_helpers)
whose requests go to an injected fetcher, and every other connection but
loopback raises. DATABASE_URL-gated like test_collection_pg.py.
"""
from __future__ import annotations

import http.client
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-b0f-"
BASE = "https://board.example.test/forums/7/"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def world(conn):
    """Two people, an exit, a forum source read by the stub, and a
    confirmed persona-less authority over it."""
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    egress = h.egress_profile(conn, P)
    source = h.source(conn, P, egress=egress)
    stub = h.StubAuthorityAdapter()
    view = h.authority(conn, recorder=recorder, confirmer=confirmer,
                       source_ids=[source], adapters=h.adapters(stub))
    return {"recorder": recorder, "confirmer": confirmer, "egress": egress,
            "source": source, "stub": stub, "authority": view}


def _fetched(url, status=200, body=b"<p>page</p>", location=None):
    from noctornal_api.pinned_http import Fetched
    return Fetched(status, http.client.HTTPMessage(), body, url, "text/html",
                   None, None, 0, "DIRECT", "127.0.0.1", location)


class Fetcher:
    def __init__(self, answer=None):
        self.answer = answer
        self.calls = []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        if isinstance(self.answer, BaseException):
            raise self.answer
        if callable(self.answer):
            return self.answer(url, **kw)
        return _fetched(url)


def _svc(conn, stub, *, fetcher=None, raw_store=None):
    from noctornal_api.collection import CollectionService
    return CollectionService(conn, h.adapters(stub), fetcher=fetcher or Fetcher(),
                             raw_store=raw_store)


def _items(*items):
    from noctornal_api.collection import FetchResult
    return lambda _ctx: FetchResult(items=list(items), http_status=200)


def _run(conn, run_id):
    return conn.execute(
        """SELECT status::text, error_class, error_detail, started_at, cursor,
                  requests, notes, requested_by, egress_profile_id,
                  authority_id, authority_target_id, items_deleted
             FROM collect.collection_run WHERE id = %s""", (run_id,)).fetchone()


def _runs(conn, source):
    return conn.execute("SELECT count(*) FROM collect.collection_run "
                        "WHERE source_id = %s", (source,)).fetchone()[0]


# --- the run row --------------------------------------------------------

def test_every_run_records_when_it_started_who_asked_and_under_what(conn, world):
    from noctornal_api.collection import Item

    world["stub"].produce = _items(Item(external_id="post:1", body="b"))
    result = _svc(conn, world["stub"]).run_once(world["source"],
                                                actor_id=world["recorder"])
    row = _run(conn, result.run_id)
    assert result.status == "OK" and row[0] == "OK"
    assert row[3] is not None, "a run's start is recorded"
    assert row[7] == world["recorder"], "who pressed Poll now"
    assert row[8] == world["egress"], "the exit it read through"
    assert str(row[9]) == world["authority"]["id"]
    assert str(row[10]) == world["authority"]["targets"][0]["id"]


def test_the_cron_is_recorded_as_the_system(conn, world):
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    assert _run(conn, result.run_id)[7] is None


def test_runs_list_newest_first_with_unrecorded_starts_last(conn, world):
    from noctornal_api.collection import CollectionService

    conn.execute("""INSERT INTO collect.collection_run (source_id, status)
                    VALUES (%s, 'OK')""", (world["source"],))
    newer = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    rows = CollectionService(conn).runs(source_id=world["source"], clearance="RED")
    assert rows[0]["id"] == str(newer.run_id)
    assert rows[-1]["started_at"] is None
    assert rows[0]["requested_by_name"] == "the system"


def test_a_caller_inside_a_transaction_is_refused(conn, world):
    from noctornal_api.collection import CollectionError

    with conn.transaction(), pytest.raises(CollectionError, match="no transaction"):
        _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)


# --- the cursor ---------------------------------------------------------

def test_the_cursor_is_threaded_back_on_the_next_poll(conn, world):
    from noctornal_api.collection import FetchResult

    seen = []

    def produce(ctx):
        seen.append(dict(world["stub"].last_cursor))
        return FetchResult(cursor={"page": len(seen)})

    world["stub"].produce = produce
    svc = _svc(conn, world["stub"])
    svc.run_once(world["source"], actor_id=None)
    svc.run_once(world["source"], actor_id=None)
    assert seen == [{}, {"page": 1}]


def test_an_empty_cursor_carries_the_previous_one_forward(conn, world):
    from noctornal_api.collection import FetchResult

    cursors = iter([{"page": 3}, {}, None])
    seen = []

    def produce(ctx):
        seen.append(dict(world["stub"].last_cursor))
        return FetchResult(cursor=next(cursors) or {})

    world["stub"].produce = produce
    svc = _svc(conn, world["stub"])
    for _ in range(3):
        svc.run_once(world["source"], actor_id=None)
    assert seen == [{}, {"page": 3}, {"page": 3}]


def test_a_drift_run_leaves_the_next_run_starting_from_the_previous_cursor(conn, world):
    from noctornal_api.collection import FetchResult, RunWarning

    answers = iter([FetchResult(cursor={"page": 1}),
                    FetchResult(cursor={"page": 9}, warnings=[RunWarning(
                        "PARSER_DRIFT", "The board's post list changed shape.")]),
                    FetchResult()])
    seen = []

    def produce(ctx):
        seen.append(dict(world["stub"].last_cursor))
        return next(answers)

    world["stub"].produce = produce
    svc = _svc(conn, world["stub"])
    svc.run_once(world["source"], actor_id=None)
    drift = svc.run_once(world["source"], actor_id=None)
    svc.run_once(world["source"], actor_id=None)
    assert drift.status == "PARTIAL"
    assert _run(conn, drift.run_id)[1] == "ParserDrift"
    assert seen[2] == {"page": 1}, "the drifted run held the cursor"


def test_a_failed_persist_does_not_advance_the_cursor(conn, world):
    from noctornal_api.collection import FetchResult

    class Boom(Exception):
        pass

    world["stub"].produce = lambda ctx: FetchResult(cursor={"page": 5})
    world["stub"].commit = lambda conn, **kw: (_ for _ in ()).throw(Boom("x"))
    svc = _svc(conn, world["stub"])
    with pytest.raises(Boom):
        svc.run_once(world["source"], actor_id=None)
    del world["stub"].commit
    seen = []
    world["stub"].produce = lambda ctx: (seen.append(dict(world["stub"].last_cursor))
                                         or FetchResult())
    svc.run_once(world["source"], actor_id=None)
    assert seen == [{}]


def test_the_cursor_is_read_after_the_lock(conn, world):
    from noctornal_api.collection import CollectionBusy, _poll_lock_key
    from noctornal_api.db import connect

    other = connect()
    try:
        other.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                      (_poll_lock_key(world["source"]),))
        with pytest.raises(CollectionBusy):
            _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
        assert world["stub"].calls == 0 and _runs(conn, world["source"]) == 0
    finally:
        other.close()


def test_a_cursor_over_16_kib_fails_the_run(conn, world):
    from noctornal_api.collection import FetchResult

    world["stub"].produce = lambda ctx: FetchResult(cursor={"x": "y" * 17000})
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    assert result.status == "FAILED"
    assert _run(conn, result.run_id)[1] == "CursorTooLarge"


def test_a_cursor_reset_starts_afresh(conn, world):
    from noctornal_api.collection import FetchResult

    seen = []

    def produce(ctx):
        seen.append(dict(world["stub"].last_cursor))
        return FetchResult(cursor={"page": 4})

    world["stub"].produce = produce
    svc = _svc(conn, world["stub"])
    svc.run_once(world["source"], actor_id=None)
    conn.execute("UPDATE collect.source SET cursor_reset_at = clock_timestamp() "
                 "WHERE id = %s", (world["source"],))
    svc.run_once(world["source"], actor_id=None)
    assert seen == [{}, {}]


# --- documents ----------------------------------------------------------

def test_author_uid_parent_ref_and_category_land_on_the_document(conn, world):
    from noctornal_api.collection import Item

    world["stub"].produce = _items(Item(
        external_id="post:10", body="hello", author_uid="u:77",
        parent_ref="post:9", category="MARKET_LISTING",
        posted_at=datetime(2026, 9, 1, tzinfo=timezone.utc)))
    _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    row = conn.execute(
        """SELECT author_uid, parent_ref, category, retain_until
             FROM collect.document WHERE source_id = %s""",
        (world["source"],)).fetchone()
    assert row == ("u:77", "post:9", "MARKET_LISTING", None)


def test_a_member_id_never_becomes_a_version_of_a_post(conn, world):
    from noctornal_api.collection import Item

    world["stub"].produce = _items(Item(external_id="post:1", body="a post"),
                                   Item(external_id="member:1", body="a member"))
    _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    rows = conn.execute(
        "SELECT external_id, version FROM collect.document WHERE source_id = %s "
        "ORDER BY external_id", (world["source"],)).fetchall()
    assert rows == [("member:1", 1), ("post:1", 1)]


def test_raw_markup_is_stored_and_its_key_is_its_digest(conn, world):
    import hashlib

    from noctornal_api.collection import Item
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    store = InMemoryDocumentRawStorage()
    world["stub"].keeps_raw = True
    world["stub"].produce = _items(Item(
        external_id="post:1", body="b",
        raw_html=b'<article><input name="_xfToken" value="t0k3n99">b</article>'))
    _svc(conn, world["stub"], raw_store=store).run_once(world["source"], actor_id=None)
    key = conn.execute("SELECT body_html_key FROM collect.document "
                       "WHERE source_id = %s", (world["source"],)).fetchone()[0]
    data = store.get(key)
    assert b"t0k3n99" not in data, "form tokens are scrubbed before storage"
    import uuid
    digest = hashlib.sha256(uuid.UUID(str(world["source"])).bytes + data).hexdigest()
    assert key == f"collect/{digest[:2]}/{digest}"


def test_raw_markup_without_a_store_is_a_named_warning_and_the_run_is_partial(conn, world):
    from noctornal_api.collection import Item

    world["stub"].keeps_raw = True
    world["stub"].produce = _items(Item(external_id="post:1", body="b",
                                        raw_html=b"<p>b</p>"))
    result = _svc(conn, world["stub"], raw_store=None).run_once(
        world["source"], actor_id=None)
    assert result.status == "PARTIAL"
    assert _run(conn, result.run_id)[1] == "RawNotKept"
    assert "not configured" in result.warnings[0]


def test_a_failed_persist_removes_the_raw_objects_it_wrote(conn, world):
    from noctornal_api.collection import Item
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    store = InMemoryDocumentRawStorage()
    world["stub"].keeps_raw = True
    world["stub"].produce = _items(Item(external_id="post:1", body="b",
                                        raw_html=b"<p>b</p>"))

    def commit(conn, **kw):
        raise RuntimeError("the adapter's own table went away")

    world["stub"].commit = commit
    with pytest.raises(RuntimeError):
        _svc(conn, world["stub"], raw_store=store).run_once(world["source"],
                                                            actor_id=None)
    assert store._objects == {}, "an object no committed document names is deleted"


def test_a_rolled_back_item_deletes_the_raw_object_it_put(conn, world):
    from noctornal_api.collection import Item
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    store = InMemoryDocumentRawStorage()
    world["stub"].keeps_raw = True
    world["stub"].produce = _items(
        Item(external_id="post:1", body="good", raw_html=b"<p>good</p>"),
        Item(external_id="post:2", body="bad", raw_html=b"<p>bad</p>"))

    def commit_item(conn, *, item, **kw):
        if item.external_id == "post:2":
            conn.execute("SELECT 1 / 0")

    world["stub"].commit_item = commit_item
    result = _svc(conn, world["stub"], raw_store=store).run_once(
        world["source"], actor_id=None)
    assert result.status == "PARTIAL" and result.items_new == 1
    assert len(store._objects) == 1, "the rolled-back item's object is gone"


def test_a_poison_item_is_skipped_and_the_next_run_moves_on(conn, world):
    from noctornal_api.collection import FetchResult, Item

    world["stub"].produce = lambda ctx: FetchResult(
        cursor={"page": 2},
        items=[Item(external_id="post:1", body="clean"),
               Item(external_id="post:2", body="a\x00b"),
               Item(external_id="post:3\x00", body="x"),
               Item(external_id="7", body="unnamespaced"),
               Item(external_id="post:4", body="x\ud800y")])
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    assert result.status == "PARTIAL"
    assert result.items_new == 3, "NUL and a lone surrogate in a body are cleaned"
    assert len([w for w in result.warnings if "skipped" in w]) == 2
    assert _run(conn, result.run_id)[4] == {"page": 2}, "the cursor moved on"


def test_a_side_table_refusal_in_commit_item_skips_the_item_and_the_cursor_moves_on(conn, world):
    from noctornal_api.collection import FetchResult, Item

    def commit_item(conn, *, item, **kw):
        if item.external_id == "post:2":
            conn.execute("SELECT 'not a uuid'::uuid")

    world["stub"].commit_item = commit_item
    world["stub"].produce = lambda ctx: FetchResult(
        cursor={"page": 7}, items=[Item(external_id="post:1", body="a"),
                                   Item(external_id="post:2", body="b")])
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    assert result.items_new == 1 and result.status == "PARTIAL"
    assert "database refused it" in result.warnings[0]
    assert _run(conn, result.run_id)[4] == {"page": 7}
    assert conn.execute("SELECT count(*) FROM collect.document WHERE source_id = %s "
                        "AND external_id = 'post:2'", (world["source"],)
                        ).fetchone()[0] == 0, "the item rolled back with its row"


def test_two_drift_polls_leave_the_source_degraded_and_listed_unhealthy(conn, world):
    from noctornal_api.collection import CollectionService, FetchResult, RunWarning

    world["stub"].produce = lambda ctx: FetchResult(warnings=[RunWarning(
        "PARSER_DRIFT", "The thread list changed shape.")])
    svc = _svc(conn, world["stub"])
    svc.run_once(world["source"], actor_id=None)
    svc.run_once(world["source"], actor_id=None)
    health = conn.execute("SELECT health FROM collect.source WHERE id = %s",
                          (world["source"],)).fetchone()[0]
    assert health == "DEGRADED"
    assert str(world["source"]) in {
        s["id"] for s in CollectionService(conn).unhealthy_sources()}


def test_a_login_wall_fails_the_run_and_stores_nothing(conn, world):
    from noctornal_api.collection import LoginWall

    def produce(ctx):
        page = ctx.fetch("threads/1/", accept_status={401, 403})
        assert page.status == 403
        raise LoginWall("The board asked for a sign-in.")

    fetcher = Fetcher(lambda url, **kw: _fetched(url, status=403))
    world["stub"].produce = produce
    result = _svc(conn, world["stub"], fetcher=fetcher).run_once(
        world["source"], actor_id=None)
    row = _run(conn, result.run_id)
    assert result.status == "FAILED" and row[1] == "LoginWall"
    assert len(row[5]) == 1 and row[5][0]["status"] == 403, (
        "the request log is on a failed run too")
    assert conn.execute("SELECT count(*) FROM collect.document WHERE source_id = %s",
                        (world["source"],)).fetchone()[0] == 0


def test_deleted_upstream_is_marked_on_the_latest_version_and_the_body_is_kept(conn, world):
    from noctornal_api.collection import FetchResult, Item

    answers = iter([
        FetchResult(items=[Item(external_id="post:1", body="v1")]),
        FetchResult(items=[Item(external_id="post:1", body="v2")]),
        FetchResult(deleted_external_ids=["post:1", "post:unknown"]),
        FetchResult(items=[Item(external_id="post:1", body="v2")])])
    world["stub"].produce = lambda ctx: next(answers)
    svc = _svc(conn, world["stub"])
    svc.run_once(world["source"], actor_id=None)
    svc.run_once(world["source"], actor_id=None)
    gone = svc.run_once(world["source"], actor_id=None)
    rows = conn.execute(
        """SELECT version, body_text, is_deleted_upstream FROM collect.document
            WHERE source_id = %s ORDER BY version""", (world["source"],)).fetchall()
    assert gone.items_deleted == 1 and _run(conn, gone.run_id)[11] == 1
    assert rows == [(1, "v1", False), (2, "v2", True)]
    back = svc.run_once(world["source"], actor_id=None)
    assert back.items_new == 0
    assert conn.execute(
        "SELECT is_deleted_upstream FROM collect.document WHERE source_id = %s "
        "AND version = 2", (world["source"],)).fetchone()[0] is False, (
        "a reappearing item clears the flag")


def test_a_refetch_of_a_purged_post_is_a_new_capture(conn, world):
    from noctornal_api.collection import Item

    world["stub"].produce = _items(Item(external_id="post:1", body="same"))
    svc = _svc(conn, world["stub"])
    svc.run_once(world["source"], actor_id=None)
    conn.execute(
        """UPDATE collect.document SET purged_at = now(), body_text = '',
                  content_sha256 = sha256(convert_to('purged:' || id::text, 'UTF8'))
            WHERE source_id = %s""", (world["source"],))
    again = svc.run_once(world["source"], actor_id=None)
    assert again.items_new == 1
    assert conn.execute("SELECT max(version) FROM collect.document WHERE source_id = %s",
                        (world["source"],)).fetchone()[0] == 2


def test_the_per_item_lookup_uses_the_source_external_version_index(conn, world):
    """The existing unique index on (source_id, external_id, version) serves
    the collector's per-item lookups, read backwards for the newest version,
    so the collector adds no second one. Sequential scans and sorts are switched off
    for the EXPLAIN because a test table is small enough that the planner
    prefers a scan, or another index on source_id plus a sort; what is
    asserted is that this index serves the query in order, unsorted."""
    with conn.transaction():
        conn.execute("SET LOCAL enable_seqscan = off")
        conn.execute("SET LOCAL enable_sort = off")
        rows = conn.execute(
            """EXPLAIN SELECT id, version FROM collect.document
                WHERE source_id = %s AND external_id = 'post:1'
                ORDER BY version DESC LIMIT 1""", (world["source"],)).fetchall()
    plan = " ".join(r[0] for r in rows)
    assert "document_source_id_external_id_version_key" in plan, plan


# --- the request log ----------------------------------------------------

def test_the_request_log_is_on_the_run_and_read_under_the_source_label(conn, world):
    from noctornal_api.collection import CollectionNotFound, CollectionService, FetchResult

    def produce(ctx):
        ctx.fetch("/threads/1/?_xfToken=17000,secretvalue1")
        return FetchResult()

    world["stub"].produce = produce
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    svc = CollectionService(conn)
    detail = svc.run_detail(result.run_id, clearance="AMBER")
    assert detail["requests"][0]["path"] == "/threads/1/"
    assert "secretvalue1" not in detail["requests"][0]["query"]
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                 (world["source"],))
    with pytest.raises(CollectionNotFound):
        svc.run_detail(result.run_id, clearance="AMBER")


def test_a_429_run_and_a_login_wall_run_each_carry_their_request_log(conn, world):
    from noctornal_api.pinned_http import HttpStatusError

    def produce(ctx):
        ctx.fetch("threads/1/")

    world["stub"].produce = produce
    fetcher = Fetcher(HttpStatusError(429, retry_after=90.0, excerpt="",
                                      location=None, location_host=None,
                                      headers=None))
    result = _svc(conn, world["stub"], fetcher=fetcher).run_once(
        world["source"], actor_id=None)
    row = _run(conn, result.run_id)
    assert result.status == "RATE_LIMITED" and row[0] == "RATE_LIMITED"
    assert row[5][0]["status"] == 429


def test_the_request_log_is_written_once(conn, world):
    import psycopg

    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    with pytest.raises(psycopg.errors.RaiseException, match="custody"):
        conn.execute("""UPDATE collect.collection_run SET requests = '[{"x": 1}]'
                        WHERE id = %s""", (result.run_id,))


# --- outcomes -----------------------------------------------------------

def test_blocked_and_rate_limited_runs_do_not_count_as_failures(conn, world):
    from noctornal_api.collection import FetchResult, RateLimited, SourceBlocked

    answers = iter([SourceBlocked("The chat moved."), RateLimited(600)])

    def produce(ctx):
        raise next(answers)

    world["stub"].produce = produce
    svc = _svc(conn, world["stub"])
    blocked = svc.run_once(world["source"], actor_id=None)
    limited = svc.run_once(world["source"], actor_id=None)
    row = conn.execute(
        "SELECT consecutive_failures, blocked_reason, next_due_at FROM collect.source "
        "WHERE id = %s", (world["source"],)).fetchone()
    assert blocked.status == "BLOCKED" and blocked.blocked_reason == "The chat moved."
    assert limited.status == "RATE_LIMITED"
    assert row[0] == 0, "neither counts toward DEGRADED"
    assert row[2] > datetime.now(timezone.utc) + timedelta(seconds=600)
    world["stub"].produce = lambda ctx: FetchResult()
    svc.run_once(world["source"], actor_id=None)
    assert conn.execute("SELECT blocked_reason FROM collect.source WHERE id = %s",
                        (world["source"],)).fetchone()[0] is None, (
        "the next good poll clears the reason")


def test_budget_spent_mid_walk_keeps_the_pages_and_advances_the_cursor(conn, world):
    from noctornal_api.collection import BudgetSpent, FetchResult, Item
    from noctornal_api.pinned_http import DeadlineExceeded

    pages = iter([_fetched(f"{BASE}p1"), DeadlineExceeded("cut", request_sent=True)])

    def answer(url, **kw):
        value = next(pages)
        if isinstance(value, BaseException):
            raise value
        return value

    def produce(ctx):
        items = []
        try:
            for n in (1, 2):
                ctx.fetch(f"p{n}")
                items.append(Item(external_id=f"post:{n}", body=f"page {n}"))
        except BudgetSpent:
            pass
        return FetchResult(items=items, cursor={"page": len(items)})

    world["stub"].produce = produce
    result = _svc(conn, world["stub"], fetcher=Fetcher(answer)).run_once(
        world["source"], actor_id=None)
    row = _run(conn, result.run_id)
    assert result.status == "OK", "a walk that stops at its budget is working as intended"
    assert result.items_new == 1 and row[4] == {"page": 1}
    assert any("stopped at its budget" in n for n in row[6])
    assert len(row[5]) == 2 and row[5][1]["status"] is None


def test_an_authority_adapter_on_a_direct_route_carries_the_egress_direct_note(conn, world):
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    assert any("read directly from this host" in n for n in result.notes)


def test_every_source_gets_a_run_context_route(conn, world):
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    ctx = world["stub"].last_context
    assert ctx is not None and ctx.route is world["stub"].last_route
    assert ctx.route.context == f"run:{result.run_id}"
    assert ctx.route.name == str(world["egress"])


def test_a_fetch_only_stub_polls_through_run_once(conn, world):
    from noctornal_api.collection import FetchResult, Item

    class FetchOnly:
        key = "stubforum"
        source_kinds = frozenset({"XENFORO"})
        requires_authority = True

        def fetch(self, **_kw):
            return FetchResult(items=[Item(external_id="post:1", body="b")])

    result = _svc(conn, FetchOnly()).run_once(world["source"], actor_id=None)
    assert result.status == "OK" and result.items_new == 1


def test_settle_runs_for_every_outcome_and_never_changes_the_run(conn, world):
    from noctornal_api.collection import SourceBlocked

    settled = []

    def settle(conn, *, status, **kw):
        settled.append(status)
        raise RuntimeError("the adapter's settle broke")

    world["stub"].settle = settle
    svc = _svc(conn, world["stub"])
    ok = svc.run_once(world["source"], actor_id=None)
    world["stub"].produce = lambda ctx: (_ for _ in ()).throw(SourceBlocked("x"))
    blocked = svc.run_once(world["source"], actor_id=None)
    assert settled == ["OK", "BLOCKED"]
    assert (ok.status, blocked.status) == ("OK", "BLOCKED")


# --- refusals before anything ------------------------------------------

def test_an_authority_adapter_with_no_ceiling_writes_no_run_and_makes_no_network_call(
        conn, world, monkeypatch):
    from noctornal_api.collection import CollectionService, SourceRefused

    monkeypatch.delenv("NOCTORNAL_FORUM_SOURCE_CEILING", raising=False)
    fetcher = Fetcher()
    world["stub"].produce = lambda ctx: ctx.fetch("x")
    with pytest.raises(SourceRefused, match="not declared"):
        _svc(conn, world["stub"], fetcher=fetcher).run_once(world["source"],
                                                           actor_id=None)
    assert fetcher.calls == [] and world["stub"].calls == 0
    assert _runs(conn, world["source"]) == 0
    held = CollectionService(conn, h.adapters(world["stub"])).held_sources()
    assert any(s["id"] == world["source"] and s["reason"] == "REFUSED" for s in held)


def test_a_forum_kind_with_the_rss_parser_is_refused(conn):
    from noctornal_api.collection import CollectionService, SourceRefused

    source = h.source(conn, P, kind="XENFORO", parser="rss")
    with pytest.raises(SourceRefused, match="does not enforce collection authority"):
        CollectionService(conn).run_once(source, actor_id=None)
    assert _runs(conn, source) == 0


def test_a_persona_id_on_a_persona_less_source_is_refused_before_a_run_row(conn, world):
    from noctornal_api.collection import CollectionError

    with pytest.raises(CollectionError, match="without a persona"):
        _svc(conn, world["stub"]).run_once(world["source"], actor_id=None,
                                          persona_id=uuid4())
    assert _runs(conn, world["source"]) == 0


def test_the_confirmer_is_refused_before_any_run_row(conn, world):
    from noctornal_api.collection_authority import AuthorityError

    with pytest.raises(AuthorityError, match="does not run the collection"):
        _svc(conn, world["stub"]).run_once(world["source"],
                                          actor_id=world["confirmer"])
    assert _runs(conn, world["source"]) == 0
    assert conn.execute("SELECT blocked_reason FROM collect.source WHERE id = %s",
                        (world["source"],)).fetchone()[0] is None


def test_a_missing_authority_found_at_poll_time_is_a_blocked_run(conn, world):
    from noctornal_api.collection_authority import CollectionAuthorityService

    CollectionAuthorityService(conn, h.adapters(world["stub"])).revoke(
        world["authority"]["id"], revoked_by=world["recorder"],
        reason="the warrant was withdrawn", by_role="record", clearance="RED")
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    row = _run(conn, result.run_id)
    assert result.status == "BLOCKED" and row[1] == "AuthorityMissing"
    assert world["stub"].calls == 0, "nothing was fetched"


def test_due_leaves_out_held_sources_and_lists_them_with_their_sentence(conn, world):
    from noctornal_api.collection import CollectionService

    uncovered = h.source(conn, P, egress=world["egress"])
    svc = CollectionService(conn, h.adapters(world["stub"]))
    due = {d["id"] for d in svc.due_sources()}
    held = {s["id"]: s for s in svc.held_sources()}
    assert world["source"] in due
    assert uncovered not in due
    assert held[uncovered]["reason"] == "AUTHORITY"
    assert "No confirmed authority covers" in held[uncovered]["sentence"]


# --- watches ------------------------------------------------------------

def _watch(conn, source, owner, **cols):
    from noctornal_api.cases import CaseService
    from datetime import date

    case = CaseService(conn).create(
        code=f"OP-CFW-{uuid4().hex[:6]}", title="framework", legal_basis="order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner)
    columns = {"keywords": None, "selector_watch": None, "regexes": None,
               "suppress_window_s": 3600, **cols}
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref, keywords,
                selector_watch, regexes, owner_user_id, suppress_window_s)
           VALUES (%s, %s, 'framework watch', 'FORUM', 'b', %s, %s, %s, %s, %s)""",
        (case, source, columns["keywords"], columns["selector_watch"],
         columns["regexes"], owner, columns["suppress_window_s"]))
    return case


def test_a_watch_on_a_typed_id_fires_on_the_author_and_on_meta_match_ids(conn, world):
    from noctornal_api.collection import Item

    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (world["recorder"],))
    _watch(conn, world["source"], world["recorder"],
           selector_watch=["u:4242", "c:-100555"], suppress_window_s=0)
    world["stub"].produce = _items(
        Item(external_id="post:1", body="nothing", author_uid="u:4242"),
        Item(external_id="post:2", body="nothing",
             meta={"match_ids": {"forwarded_from": "c:-100555", "BAD": "c:-100555"}}))
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    matched = sorted(r[0] for r in conn.execute(
        """SELECT h.matched_on::text FROM collect.watch_hit h
             JOIN collect.document d ON d.id = h.document_id
            WHERE d.source_id = %s""", (world["source"],)).fetchall())
    assert result.watch_hits == 2
    assert any("author:u:4242" in m for m in matched)
    assert any("forwarded_from:c:-100555" in m for m in matched)
    assert not any("BAD:" in m for m in matched), "labels are [a-z_] only"


def test_the_same_watch_hit_twice_is_one_row(conn, world):
    from noctornal_api.collection import Item

    _watch(conn, world["source"], world["recorder"], keywords=["selling"],
           suppress_window_s=0)
    world["stub"].produce = _items(Item(external_id="post:1", body="selling"))
    svc = _svc(conn, world["stub"])
    first = svc.run_once(world["source"], actor_id=None)
    second = svc.run_once(world["source"], actor_id=None)
    assert (first.status, second.status) == ("OK", "OK")
    assert (first.watch_hits, second.watch_hits) == (1, 0)


def test_a_purged_document_never_gets_a_watch_hit(conn, world):
    from noctornal_api.collection import CollectionService, Item

    _watch(conn, world["source"], world["recorder"], keywords=["selling"],
           suppress_window_s=0)
    world["stub"].produce = _items(Item(external_id="post:1", body="quiet"))
    svc = _svc(conn, world["stub"])
    svc.run_once(world["source"], actor_id=None)
    conn.execute("UPDATE collect.document SET purged_at = now(), body_text = '' "
                 "WHERE source_id = %s", (world["source"],))
    hits = CollectionService(conn)._match_watches(
        world["source"], uuid4(), Item(external_id="post:1", body="selling"),
        svc._watches(world["source"]), {})
    assert hits == 0


# --- RSS, exactly as before, through the passive route -----------------

FEED = b"""<?xml version="1.0"?><rss><channel>
<item><title>Selling access</title><guid>t-1</guid><description>d</description></item>
</channel></rss>"""


def test_rss_polls_exactly_as_before(conn, world):
    from noctornal_api.collection import CollectionService, FetchResult, parse_rss

    source = h.source(conn, P, kind="RSS", parser="rss", egress=None)
    _watch(conn, source, world["recorder"], regexes=["[unclosed"])

    class Stub:
        key, version = "rss", "test"

        def fetch(self, **kw):
            self.kw = kw
            return FetchResult(items=parse_rss(FEED), http_status=200)

    stub = Stub()
    result = CollectionService(conn, {"rss": stub}).run_once(source, actor_id=None)
    row = conn.execute(
        "SELECT category, retain_until, body_html_key FROM collect.document "
        "WHERE source_id = %s", (source,)).fetchone()
    run = _run(conn, result.run_id)
    assert row == ("FORUM_POST", None, None)
    assert result.status == "PARTIAL" and run[1] == "WatchPatternError"
    assert run[8] is None, "a passive run records no egress profile"
    assert stub.kw["context"] is None and stub.kw["etag"] is None
    assert stub.kw["route"].name == "passive"
    assert stub.kw["route"].context == f"run:{result.run_id}"
    assert conn.execute("SELECT health FROM collect.source WHERE id = %s",
                        (source,)).fetchone()[0] == "OK"


def test_a_route_refusal_on_an_rss_poll_is_blocked_not_failed(conn):
    from noctornal_api.collection import CollectionService
    from noctornal_api.pinned_http import RouteUnavailable

    source = h.source(conn, P, kind="RSS", parser="rss")

    class Refused:
        key, version = "rss", "test"

        def fetch(self, **kw):
            raise RouteUnavailable("the proxy is busy", code="proxy_busy")

    result = CollectionService(conn, {"rss": Refused()}).run_once(source,
                                                                  actor_id=None)
    assert result.status == "BLOCKED"
    assert conn.execute("SELECT consecutive_failures FROM collect.source "
                        "WHERE id = %s", (source,)).fetchone()[0] == 0



def test_rss_polls_through_the_passive_route_once_a_proxy_is_configured(
        conn, monkeypatch):
    """With a proxy configured and a route provider present, an RSS poll
    takes the PROXY passive route with its run as the context, and its
    CONNECT carries `persona.passive~run.<run id>` to the one listener. The
    stub proxy checks the wire only: the egress proxy's suites run the same
    poll against its real listener, which also checks that a passive run
    records no exit."""
    from egress_contract_cases import STUB_KEY, Origin, StubProxy, contract_token

    from noctornal_api import egress, egress_policy
    from noctornal_api.collection import CollectionService

    origin = Origin(body=FEED)
    try:
        with StubProxy() as stub:
            stub.names["feed.example.test"] = "127.0.0.1"
            token = contract_token(STUB_KEY, egress_policy.wire_username(
                "persona", egress_policy.PASSIVE_PROFILE))

            class Provider:
                PROVIDER_CONTRACT = 1

                @staticmethod
                def route_parts(kind, name, *, conn, mode, production,
                                declared, internal, **_kw):
                    policy = egress_policy.RoutePolicy(
                        kind, any_public=True, admission="proxy")
                    return egress.RouteParts(policy, token)

            monkeypatch.setattr(egress, "_route_provider", lambda: Provider)
            monkeypatch.setenv(egress.PROXY_URL_ENV, f"http://127.0.0.1:{stub.port}")
            source = h.source(
                conn, P, kind="RSS", parser="rss",
                base_url=f"http://feed.example.test:{origin.server_port}/feed.xml")
            result = CollectionService(conn).run_once(source, actor_id=None)
            assert result.status == "OK", result.error
            assert result.items_new == 1
            usernames = [r["username"] for r in stub.records]
            assert usernames == [f"persona.passive~run.{result.run_id}"]
            assert _run(conn, result.run_id)[8] is None
    finally:
        origin.close()


def test_the_source_listing_says_a_parserless_source_is_never_polled(conn):
    """The listing's refusal for a source with no parser is a sentence, not
    'No parser in this build is called None.' (screenshot review of the
    Sources pane, 2026-09-24)."""
    from noctornal_api.collection import CollectionService

    manual = h.source(conn, P, kind="MANUAL", parser=None, base_url=None)
    missing = h.source(conn, P, kind="RSS", parser="gone-parser")
    rows = {r["id"]: r for r in CollectionService(conn, h.adapters())
            .sources(clearance="RED")}
    assert rows[str(manual)]["refusal"] == (
        "This source has no parser, so nothing polls it.")
    assert rows[str(missing)]["refusal"] == (
        "No parser in this build is called gone-parser.")
