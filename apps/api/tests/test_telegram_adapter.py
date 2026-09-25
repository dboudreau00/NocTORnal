"""The Telegram adapter against a fake transport, with no database and no
network (roadmap F5.3, telegram, 2026-09-24).

A poll's window and cursor, the recheck of edits and deletions, the
outcomes Telegram gives, hostile messages, the session budget and its
backstop, the pacing of a slow chat and the custody log of every RPC.
"""
from __future__ import annotations

import json
import threading
import time

import pytest

import telegram_fake as tf


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    tf.guard_sockets(monkeypatch)


def _adapter(fx, clock=None, **kw):
    from noctornal_api.telegram import TelegramAdapter

    factory = tf.FakeFactory(fx, **kw)
    clock = clock or tf.FakeClock()
    return TelegramAdapter(factory, sleep=clock.sleep, clock=clock), factory


def _poll(fx, *, cursor=None, access_mode="PUBLIC_READ", max_rps=1.0, clock=None,
          plan_kw=None, ctx_kw=None, **kw):
    adapter, factory = _adapter(fx, clock, **kw)
    source = tf.source_row(access_mode=access_mode, max_rps=max_rps)
    ctx = tf.FakeRunContext(source, persona_id=source.collection_account_id,
                            **(ctx_kw or {}))
    adapter.prime(tf.plan_for(fx, source, **(plan_kw or {})))
    result = adapter.fetch(base_url=None, cursor=cursor or {}, context=ctx,
                           route=ctx.route)
    return result, factory, ctx, adapter


def test_first_poll_takes_the_newest_window_and_sets_the_cursor():
    result, factory, _ctx, _a = _poll(tf.fixture("channel_posts"))
    ids = [int(i.external_id.split("/")[1]) for i in result.items]
    assert ids == list(range(51, 251)), "the newest 200, oldest first"
    assert result.cursor == {"v": 1, "last_message_id": 250, "read_as": "u:700000001"}
    history = [kw for name, kw in factory.calls if name == "history"]
    assert all(kw["newest_first"] and kw["limit"] <= 100 for kw in history)
    assert result.items[0].external_id == "c:1300000001/51"
    assert result.items[0].url == "https://t.me/c/1300000001/51"
    # A channel post's sender is the channel itself, typed.
    assert result.items[0].author_uid == "c:1300000001"


def test_the_cursor_only_advances_past_what_was_returned():
    fx = tf.fixture("channel_posts")
    result, factory, *_ = _poll(fx, cursor={"v": 1, "last_message_id": 240,
                                            "read_as": "u:700000001"})
    assert [i.external_id for i in result.items] == [
        f"c:1300000001/{n}" for n in range(241, 251)]
    assert result.cursor["last_message_id"] == 250
    assert [kw["min_id"] for name, kw in factory.calls if name == "history"] == [240]
    quiet, *_ = _poll(fx, cursor={"v": 1, "last_message_id": 250, "read_as": "u:700000001"})
    assert quiet.items == [] and quiet.cursor["last_message_id"] == 250


def test_a_backlog_drains_oldest_first_across_runs():
    fx = tf.fixture("channel_posts")
    fx["generate"]["count"] = 1200
    first, *_ = _poll(fx, cursor={"v": 1, "last_message_id": 100, "read_as": "u:700000001"})
    ids = [int(i.external_id.split("/")[1]) for i in first.items]
    assert ids == list(range(101, 601)), "500 per run, oldest first"
    second, *_ = _poll(fx, cursor=first.cursor)
    assert [int(i.external_id.split("/")[1]) for i in second.items][0] == 601
    assert second.cursor["last_message_id"] == 1100


def test_a_basic_group_cursor_from_another_account_is_ignored():
    fx = tf.fixture("basic_group")
    result, factory, *_ = _poll(fx, access_mode="MEMBER",
                                cursor={"v": 1, "last_message_id": 101,
                                        "read_as": "u:700000009"},
                                plan_kw={"member_since": "2026-09-22"})
    history = [kw for name, kw in factory.calls if name == "history"]
    assert history and history[0]["newest_first"], "a first-poll window, not min_id 101"
    assert {i.external_id for i in result.items} == {
        "g:4000001/101@u:700000001", "g:4000001/102@u:700000001"}
    assert all(i.url is None for i in result.items), "no link to a basic group"


def test_an_edit_on_recheck_becomes_an_item_and_an_unchanged_message_does_not():
    fx = tf.fixture("recheck_edit_delete")
    result, factory, *_ = _poll(
        fx, cursor={"v": 1, "last_message_id": 3, "read_as": "u:700000001"},
        plan_kw={"recheck": ((1, None), (2, None), (3, None))})
    assert [i.body for i in result.items] == ["second version"]
    assert result.items[0].external_id == "c:1300000005/1"
    assert result.deleted_external_ids == ["c:1300000005/2"]
    asked = [kw["ids"] for name, kw in factory.calls if name == "messages_by_id"]
    assert asked == [[1, 2, 3]]


def test_a_recheck_answer_that_does_not_line_up_marks_nothing_deleted():
    from noctornal_api import telegram

    fx = tf.fixture("recheck_edit_delete")
    adapter, factory = _adapter(fx)

    async def short(chat, ids):
        return [None]

    source = tf.source_row()
    ctx = tf.FakeRunContext(source, persona_id=source.collection_account_id)
    adapter.prime(tf.plan_for(fx, source, recheck=((1, None), (2, None))))
    original = tf.FakeTransport.messages_by_id
    tf.FakeTransport.messages_by_id = lambda self, chat, ids: short(chat, ids)
    try:
        result = adapter.fetch(base_url=None, cursor={"v": 1, "last_message_id": 3,
                                                      "read_as": "u:700000001"},
                               context=ctx, route=ctx.route)
    finally:
        tf.FakeTransport.messages_by_id = original
    assert result.deleted_external_ids == []
    assert isinstance(result, telegram.TelegramFetchResult)


def test_flood_wait_is_reported_with_telegrams_own_seconds():
    """The collection foundation adds the margin once;
    the adapter carries Telegram's number unchanged."""
    from noctornal_api import telegram

    with pytest.raises(telegram.TelegramFloodWait) as caught:
        _poll(tf.fixture("channel_posts"),
              errors={"history": telegram.TelegramFloodWait(37)})
    assert caught.value.retry_after_s == 37.0
    assert "37 seconds" in str(caught.value)


def test_the_custody_log_has_one_entry_per_rpc_and_keeps_them_on_a_flood_wait():
    from noctornal_api import telegram

    result, factory, ctx, _a = _poll(tf.fixture("channel_posts"))
    sent = [name for name in factory.methods() if name not in ("close",)]
    assert len(ctx.requests) == len(sent) == 4, (sent, ctx.requests)
    assert ctx.requests[0]["target"].startswith("connect")
    assert all("examplenews" not in r["target"] and "Example" not in r["target"]
               for r in ctx.requests), "no username or title in the custody log"
    adapter, factory = _adapter(tf.fixture("channel_posts"),
                                errors={"history": telegram.TelegramFloodWait(5)})
    source = tf.source_row()
    ctx = tf.FakeRunContext(source, persona_id=source.collection_account_id)
    adapter.prime(tf.plan_for(tf.fixture("channel_posts"), source))
    with pytest.raises(telegram.TelegramFloodWait):
        adapter.fetch(base_url=None, cursor={}, context=ctx, route=ctx.route)
    assert [r["status"] for r in ctx.requests] == [200, 200, None]
    assert ctx.paced == 1, "the source and persona gap, once, before the session"


def test_the_adapter_calls_only_the_read_methods():
    for name in ("channel_posts", "megagroup_threads", "recheck_edit_delete",
                 "service_messages"):
        fx = tf.fixture(name)
        member = fx["chat"].get("is_member")
        _result, factory, *_ = _poll(
            fx, access_mode="MEMBER" if member else "PUBLIC_READ",
            plan_kw={"member_since": "x"} if member else None,
            cursor={"v": 1, "last_message_id": 1, "read_as": "u:700000001"})
        assert set(factory.methods()) <= tf.ALLOWED_FOR_POLL, factory.methods()


def test_a_recycled_username_is_refused_not_followed():
    from noctornal_api import telegram

    fx = tf.fixture("megagroup_threads")
    source = tf.source_row()
    plan = tf.plan_for(fx, source, own_hash=False)
    moved = dict(fx, chat=dict(fx["chat"], peer_id=1300000099))
    adapter, factory = _adapter(moved)
    ctx = tf.FakeRunContext(source, persona_id=source.collection_account_id)
    adapter.prime(plan)
    with pytest.raises(telegram.TelegramNameMoved):
        adapter.fetch(base_url=None, cursor={}, context=ctx, route=ctx.route)
    assert "history" not in factory.methods()


def test_a_session_for_another_account_is_refused():
    from noctornal_api import telegram

    fx = dict(tf.fixture("channel_posts"), me="u:700000009")
    with pytest.raises(telegram.TelegramWrongAccount) as caught:
        _poll(fx)
    assert caught.value.lock_code == "WRONG_ACCOUNT"


def test_a_public_chat_the_persona_joined_is_refused():
    from noctornal_api import telegram

    fx = tf.fixture("channel_posts")
    fx["chat"]["is_member"] = True
    with pytest.raises(telegram.TelegramRefused, match="now a member"):
        _poll(fx)


def test_a_member_chat_the_persona_left_is_refused_and_remembered_for_settle():
    from noctornal_api import telegram

    fx = tf.fixture("megagroup_threads")
    fx["chat"]["is_member"] = False
    adapter, _factory = _adapter(fx)
    source = tf.source_row(access_mode="MEMBER")
    ctx = tf.FakeRunContext(source, persona_id=source.collection_account_id)
    adapter.prime(tf.plan_for(fx, source, member_since="2026-09-01"))
    with pytest.raises(telegram.TelegramRefused, match="no longer a member"):
        adapter.fetch(base_url=None, cursor={}, context=ctx, route=ctx.route)
    assert adapter._settle[source.id] == {"membership_lost": True}


def test_the_session_is_resealed_when_telegram_moves_it():
    moved = tf.make_session(dc=4, ip="149.154.167.91")
    result, *_ = _poll(tf.fixture("channel_posts"), session_after=moved)
    assert json.loads(result.secret_update)["session"] == moved
    unmoved, *_ = _poll(tf.fixture("channel_posts"))
    assert unmoved.secret_update is None


def test_a_chat_title_never_enters_the_matching_haystack():
    result, *_ = _poll(tf.fixture("megagroup_threads"))
    assert result.items and all(i.title is None for i in result.items)


def test_typed_ids_keep_a_user_and_a_channel_with_one_number_apart():
    result, *_ = _poll(tf.fixture("megagroup_threads"))
    by_id = {i.external_id: i for i in result.items}
    assert by_id["c:1300000003/10"].author_uid == "u:1300000001"
    assert by_id["c:1300000003/12"].author_uid == "c:1300000003", "anonymous admin"
    fwd = by_id["c:1300000003/13"]
    assert fwd.meta["match_ids"] == {"forwarded_from": "c:1300000002",
                                     "via_bot": "u:93372553"}
    assert "author" not in fwd.meta["match_ids"], "the author is item.author_uid"
    hidden = by_id["c:1300000003/14"].meta["telegram_message"]
    assert hidden["fwd_from_uid"] is None and hidden["fwd_from_name"] == "Someone Hidden"
    assert hidden["media_kind"] == "photo"
    assert by_id["c:1300000003/11"].parent_ref == "c:1300000003/10"
    assert by_id["c:1300000003/11"].thread_ref == "c:1300000003/t:10"
    assert by_id["c:1300000003/11"].url == "https://t.me/c/1300000003/10/11"


def test_service_messages_are_marked_and_the_personas_own_join_is_is_self():
    result, *_ = _poll(tf.fixture("service_messages"), access_mode="MEMBER",
                       plan_kw={"member_since": "2026-09-01"})
    by_id = {i.external_id: i.meta["telegram_message"] for i in result.items}
    joined = by_id["c:1300000006/5"]
    assert joined["is_service"] and joined["service_action"] == "MessageActionChatJoinedByLink"
    assert not joined["is_self"]
    own = by_id["c:1300000006/6"]
    assert own["is_service"] and own["is_self"]
    assert not by_id["c:1300000006/7"]["is_service"]


def test_a_poisoned_message_is_skipped_named_and_passed():
    from noctornal_api import telegram
    from noctornal_api.collection import ITEM_SKIPPED

    result, *_ = _poll(tf.fixture("hostile_messages"),
                       cursor={"v": 1, "last_message_id": 19, "read_as": "u:700000001"})
    by_id = {int(i.external_id.split("/")[1]): i for i in result.items}
    assert 25 not in by_id and 26 in by_id, "the next message is still read"
    assert result.cursor["last_message_id"] == 26, "the cursor moves past it"
    skipped = [w for w in result.warnings if w.kind == ITEM_SKIPPED]
    assert len(skipped) == 1 and "message 25" in skipped[0].text
    assert "1 message could not be stored and was skipped" in skipped[0].text
    assert "\x00" not in by_id[20].body and "\ufffd" in by_id[20].body
    assert "\ud800" not in by_id[21].body
    assert len(by_id[22].body) == telegram.MAX_MESSAGE_CHARS
    assert by_id[22].body.endswith(telegram.TRUNCATION_MARK)
    assert "\u202e" not in by_id[23].author_handle
    assert len(by_id[24].author_handle) <= telegram.MAX_NAME_CHARS
    assert by_id[24].meta["telegram_message"]["sender_handle_at_capture"] == \
        by_id[24].author_handle


def test_no_bare_positive_id_reaches_an_item():
    import re

    typed = re.compile(r"^[ucg]:[1-9][0-9]{0,19}")
    for name in ("channel_posts", "megagroup_threads", "service_messages",
                 "hostile_messages"):
        fx = tf.fixture(name)
        member = fx["chat"].get("is_member")
        result, *_ = _poll(fx, access_mode="MEMBER" if member else "PUBLIC_READ",
                           plan_kw={"member_since": "x"} if member else None)
        for item in result.items:
            assert typed.match(item.external_id)
            for value in (item.author_uid, item.parent_ref):
                assert value is None or typed.match(value), value
            record = item.meta["telegram_message"]
            for key in ("sender_uid", "fwd_from_uid", "via_bot_uid", "seen_via_uid",
                        "chat_durable_id"):
                assert record[key] is None or typed.match(record[key]), (key, record[key])


def test_a_direct_route_is_refused_before_any_transport_is_built():
    from noctornal_api import telegram
    from noctornal_api.egress_policy import PUBLIC_POLICY, EgressRoute

    fx = tf.fixture("channel_posts")
    adapter, factory = _adapter(fx)
    source = tf.source_row()
    direct = EgressRoute.direct("persona", "passive", PUBLIC_POLICY)
    ctx = tf.FakeRunContext(source, route=direct)
    adapter.prime(tf.plan_for(fx, source))
    with pytest.raises(telegram.TelegramEgressRefused, match="only through the egress proxy"):
        adapter.fetch(base_url=None, cursor={}, context=ctx, route=direct)
    assert factory.transports == []


def test_a_poll_without_a_plan_fails_rather_than_guessing():
    from noctornal_api.collection import CollectionError

    adapter, _factory = _adapter(tf.fixture("channel_posts"))
    source = tf.source_row()
    ctx = tf.FakeRunContext(source)
    with pytest.raises(CollectionError, match="carried no plan"):
        adapter.fetch(base_url=None, cursor={}, context=ctx, route=ctx.route)


def test_a_slow_chat_drains_over_several_polls():
    """A chat at 0.05 requests a second waits 16 to 28
    seconds between RPCs, and a session of 90 seconds cannot carry a whole
    backlog. The session stops starting RPCs it could not finish, keeps what
    it read, says so, and the next poll carries on."""
    from noctornal_api.collection import BUDGET_SPENT

    fx = tf.fixture("channel_posts")
    fx["generate"]["count"] = 1200
    cursor = {"v": 1, "last_message_id": 100, "read_as": "u:700000001"}
    seen = []
    for _ in range(4):
        clock = tf.FakeClock()
        result, *_ = _poll(fx, cursor=cursor, max_rps=0.05, clock=clock)
        seen.extend(int(i.external_id.split("/")[1]) for i in result.items)
        assert any(w.kind == BUDGET_SPENT for w in result.warnings)
        assert clock.now - 1000.0 <= 85.0
        cursor = result.cursor
    assert seen == list(range(101, 101 + len(seen))), "no gap, no repeat"
    assert len(seen) >= 300


def test_an_ordinary_timeout_closes_the_session_and_says_so():
    from noctornal_api.telegram import TelegramAdapter, TelegramSessionTimedOut

    fx = tf.fixture("channel_posts")
    factory = tf.FakeFactory(fx, hang=True)
    adapter = TelegramAdapter(factory, session_seconds=0.3, backstop_seconds=5)
    source = tf.source_row()
    ctx = tf.FakeRunContext(source, persona_id=source.collection_account_id)
    adapter.prime(tf.plan_for(fx, source))
    with pytest.raises(TelegramSessionTimedOut):
        adapter.fetch(base_url=None, cursor={}, context=ctx, route=ctx.route)
    assert factory.transports[0].calls[-1][0] == "close", "cancellation closed it"


def test_the_run_budget_abandons_a_slow_session_on_a_daemon_thread():
    """A session that blocks its own thread cannot be cancelled: the caller
    stops waiting at the budget plus the backstop, and the persona rests."""
    from noctornal_api.telegram import TelegramSessionAbandoned, run_blocking

    started = []

    async def stuck():
        started.append(threading.current_thread())
        time.sleep(3)

    t0 = time.monotonic()
    with pytest.raises(TelegramSessionAbandoned):
        run_blocking(stuck, 0.2, backstop_s=0.3)
    assert time.monotonic() - t0 < 2.0
    assert started and started[0].daemon


def test_redaction_reaches_the_session_thread():
    """A new thread starts with an empty context, so
    the lease's secrets were out of scope where the library runs."""
    from noctornal_api.collection import redact, secret_in_scope
    from noctornal_api.telegram import run_blocking

    secret = "0123456789abcdef0123456789abcdef"

    async def inside():
        return redact(f"library said {secret}")

    with secret_in_scope(secret):
        said = run_blocking(inside, 5)
    assert secret not in said and "library said" in said


def test_an_exception_outside_every_table_carries_its_class_name_only():
    from noctornal_api.telegram import TelegramTransportFailed, run_blocking

    async def boom():
        raise ValueError("Could not find the input entity for @secret_username")

    with pytest.raises(TelegramTransportFailed) as caught:
        run_blocking(boom, 5)
    assert "secret_username" not in str(caught.value)
    assert "ValueError" in str(caught.value)
