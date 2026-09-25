"""Telegram polls through the collection foundation's run_once, with a fake
transport and no network (roadmap F5.3, 2026-09-24).

The authority before any transport, the member scope, Telegram's answers
on the persona before its lock is released, the documents and their
capture records, deletions and edits, watches on typed ids, a migrated
group, the guards on the chat and message rows, the ceilings, the missing
library and the missing proxy, and the custody log. DATABASE_URL-gated.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

import collection_helpers as h
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-tgcol-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    tf.guard_sockets(monkeypatch)
    c = connect()
    yield c
    tp.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def routes(monkeypatch):
    return tf.patch_routes(monkeypatch)


def _people(conn):
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    manager, _ = h.user(conn, P, roles=("COLLECTOR",))
    return recorder, confirmer, manager


@pytest.fixture
def world(conn, routes):
    recorder, confirmer, manager = _people(conn)
    pid, egress, uid = tp.persona(conn, P)
    ch = tp.chat(conn, P, persona_id=pid, resolved_by=recorder)
    view = h.authority(conn, recorder=recorder, confirmer=confirmer,
                       persona_id=pid, source_ids=[ch["source"]])
    return {"recorder": recorder, "confirmer": confirmer, "manager": manager,
            "persona": pid, "egress": egress, "uid": uid, "source": ch["source"],
            "chat": ch, "authority": view, "routes": routes}


def _poll(conn, world, fx=None, *, adapter_kw=None, source=None, **fake):
    from noctornal_api.collection import CollectionService, RssAdapter
    from noctornal_api.telegram import TelegramAdapter

    fx = fx or tp.fixture_for(world["chat"]["spec"], world["uid"], tp.messages(1, 5))
    factory = tf.FakeFactory(fx, **fake)
    adapter = TelegramAdapter(factory, sleep=tf._no_sleep, **(adapter_kw or {}))
    svc = CollectionService(conn, {"rss": RssAdapter(), "telegram": adapter},
                            sleep=lambda _s: None)
    return svc.run_once(source or world["source"], actor_id=None), factory, adapter


def _persona_row(conn, pid):
    return conn.execute(
        """SELECT machine_hold_until, machine_hold_reason, machine_lock_code,
                  last_request_at FROM collect.collection_account WHERE id = %s""",
        (pid,)).fetchone()


# --- the gate before any network --------------------------------------------

def test_a_poll_without_a_confirmed_target_is_blocked_and_never_builds_a_transport(
        conn, routes):
    recorder, confirmer, _m = _people(conn)
    pid, _e, uid = tp.persona(conn, P)
    ch = tp.chat(conn, P, persona_id=pid, resolved_by=recorder)
    h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[ch["source"]], confirm=False)
    world = {"source": ch["source"], "chat": ch, "uid": uid}
    result, factory, _a = _poll(conn, world)
    assert result.status == "BLOCKED" and factory.transports == []
    assert "second person" in result.blocked_reason


def test_a_member_chat_not_yet_joined_is_blocked_before_any_network(conn, routes):
    recorder, confirmer, _m = _people(conn)
    pid, _e, uid = tp.persona(conn, P)
    ch = tp.chat(conn, P, persona_id=pid, resolved_by=recorder, access_mode="MEMBER")
    h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[ch["source"]], scope="MEMBER_READ",
                member_ref="COVERT-2026-9")
    result, factory, _a = _poll(conn, {"source": ch["source"], "chat": ch, "uid": uid})
    assert result.status == "BLOCKED" and factory.transports == []
    assert "has not joined it" in result.blocked_reason


def test_a_member_chat_is_polled_under_the_member_authority(conn, routes):
    recorder, confirmer, _m = _people(conn)
    pid, _e, uid = tp.persona(conn, P)
    ch = tp.chat(conn, P, persona_id=pid, resolved_by=recorder, access_mode="MEMBER",
                 member_since=True)
    public = h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                         source_ids=[ch["source"]])
    world = {"source": ch["source"], "chat": ch, "uid": uid}
    blocked, _f, _a = _poll(conn, world)
    assert blocked.status == "BLOCKED", "a public authority does not cover a member read"
    member = h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                         source_ids=[ch["source"]], scope="MEMBER_READ",
                         member_ref="COVERT-2026-9")
    result, _f, _a = _poll(conn, world)
    assert result.status == "OK", result.error
    used = conn.execute("SELECT authority_id FROM collect.collection_run WHERE id = %s",
                        (result.run_id,)).fetchone()[0]
    assert str(used) == member["id"] != public["id"]


# --- a poll that reads -----------------------------------------------------------

def test_messages_land_as_documents_with_typed_author_ids_and_telegram_rows(conn, world):
    result, _f, _a = _poll(conn, world)
    assert result.status == "OK" and result.items_new == 5, result.error
    rows = conn.execute(
        """SELECT d.external_id, d.author_uid, d.category, d.title,
                  m.chat_durable_id, m.message_id, m.seen_via_uid, m.sender_uid
             FROM collect.document d
             JOIN collect.telegram_message m ON m.document_id = d.id
            WHERE d.source_id = %s ORDER BY m.message_id""",
        (world["source"],)).fetchall()
    durable = world["chat"]["durable_id"]
    assert [r[0] for r in rows] == [f"{durable}/{i}" for i in range(1, 6)]
    assert all(r[1] == r[7] and r[1].startswith("u:") for r in rows)
    assert {r[2] for r in rows} == {"CHAT_EXPORT"} and {r[3] for r in rows} == {None}
    assert {r[4] for r in rows} == {durable} and {r[6] for r in rows} == {world["uid"]}


def test_the_run_records_persona_egress_authority_start_time_and_every_rpc(conn, world):
    result, factory, _a = _poll(conn, world)
    row = conn.execute(
        """SELECT collection_account_id, egress_profile_id, authority_id, started_at,
                  requests, cursor FROM collect.collection_run WHERE id = %s""",
        (result.run_id,)).fetchone()
    assert row[0] == world["persona"] and row[1] == world["egress"]
    assert str(row[2]) == world["authority"]["id"] and row[3] is not None
    sent = [m for m in factory.methods() if m != "close"]
    assert len(row[4]) == len(sent) >= 3, (sent, row[4])
    assert row[5] == {"v": 1, "last_message_id": 5, "read_as": world["uid"]}
    usernames = [p["username"] for p in factory.proxies]
    assert usernames and all(u.endswith(f"~run.{result.run_id}") for u in usernames)


def test_the_persona_and_source_clocks_advance_to_the_sessions_end(conn, world):
    # Stamped at the END (settle), after the run was finished, so the next
    # session of this account waits its gap from there; the pacing before
    # the session stamps the start only. The database's own clock throughout.
    result, _f, _a = _poll(conn, world)
    finished = conn.execute("SELECT finished_at FROM collect.collection_run WHERE id = %s",
                            (result.run_id,)).fetchone()[0]
    last = _persona_row(conn, world["persona"])[3]
    source_last = conn.execute("SELECT last_request_at FROM collect.source WHERE id = %s",
                               (world["source"],)).fetchone()[0]
    assert last >= finished and source_last >= finished


def test_telegram_documents_get_the_chat_export_retention_clock(conn, world):
    _poll(conn, world)
    days = conn.execute("SELECT retain_days FROM core.retention_rule "
                        "WHERE category = 'CHAT_EXPORT'").fetchone()[0]
    rows = conn.execute(
        "SELECT retain_until - captured_at FROM collect.document WHERE source_id = %s",
        (world["source"],)).fetchall()
    assert rows and all(abs(r[0] - timedelta(days=days)) < timedelta(minutes=1)
                        for r in rows)


def test_deleted_upstream_is_marked_once_and_the_body_is_kept(conn, world):
    spec, uid = world["chat"]["spec"], world["uid"]
    _poll(conn, world, tp.fixture_for(spec, uid, tp.messages(1, 3)))
    fx = tp.fixture_for(spec, uid, tp.messages(1, 3), recheck={"2": None})
    result, factory, _a = _poll(conn, world, fx)
    assert result.items_deleted == 1
    asked = [kw["ids"] for name, kw in factory.calls if name == "messages_by_id"]
    assert sorted(asked[0]) == [1, 2, 3]
    gone = conn.execute(
        """SELECT d.is_deleted_upstream, d.body_text, m.deleted_seen_at
             FROM collect.document d JOIN collect.telegram_message m ON m.document_id = d.id
            WHERE d.source_id = %s AND m.message_id = 2""", (world["source"],)).fetchone()
    assert gone[0] is True and gone[1] == "message 2" and gone[2] is not None
    _r, again, _a = _poll(conn, world, fx)
    asked = [kw["ids"] for name, kw in again.calls if name == "messages_by_id"]
    assert 2 not in asked[0], "a marked deletion is never rechecked"
    with pytest.raises(psycopg.errors.RaiseException, match="capture record is fixed"):
        conn.execute("UPDATE collect.telegram_message SET deleted_seen_at = NULL "
                     "WHERE source_id = %s AND message_id = 2", (world["source"],))


def test_an_edit_is_a_new_version_with_supersedes_id(conn, world):
    spec, uid = world["chat"]["spec"], world["uid"]
    _poll(conn, world, tp.fixture_for(spec, uid, tp.messages(1, 2)))
    edited = dict(tp.messages(1, 1)[0], text="edited text",
                  edit_date="2026-09-25T10:00:00+00:00")
    _poll(conn, world, tp.fixture_for(spec, uid, tp.messages(1, 2), recheck={"1": edited}))
    rows = conn.execute(
        """SELECT d.version, d.supersedes_id IS NOT NULL, d.body_text, m.edit_date
             FROM collect.document d JOIN collect.telegram_message m ON m.document_id = d.id
            WHERE d.source_id = %s AND m.message_id = 1 ORDER BY d.version""",
        (world["source"],)).fetchall()
    assert [(r[0], r[1], r[2]) for r in rows] == [
        (1, False, "message 1"), (2, True, "edited text")]
    assert rows[1][3] is not None


def test_a_watch_on_a_typed_id_fires_on_author_and_forward(conn, world):
    from datetime import date
    from uuid import uuid4

    from noctornal_api.cases import CaseService

    case = CaseService(conn).create(
        code=f"OP-TGC-{uuid4().hex[:6]}", title="tg", legal_basis="order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=world["recorder"], created_by=world["recorder"])
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref, selector_watch,
                owner_user_id, suppress_window_s)
           VALUES (%s, %s, 'tg watch', 'TELEGRAM_CHAT', %s, %s, %s, 0)""",
        (case, world["source"], world["chat"]["durable_id"],
         ["u:700000002", "c:1300000077"], world["recorder"]))
    msgs = [{"id": 1, "date": "2026-09-24T10:00:00+00:00", "text": "hello",
             "from": {"type": "user", "id": 700000002}},
            {"id": 2, "date": "2026-09-24T10:01:00+00:00", "text": "forwarded",
             "from": {"type": "user", "id": 700000003},
             "fwd": {"from": {"type": "channel", "id": 1300000077}}}]
    result, _f, _a = _poll(conn, world, tp.fixture_for(world["chat"]["spec"],
                                                      world["uid"], msgs))
    assert result.watch_hits == 2
    matched = sorted(str(r[0]) for r in conn.execute(
        """SELECT h.matched_on FROM collect.watch_hit h
             JOIN collect.watch w ON w.id = h.watch_id WHERE w.source_id = %s""",
        (world["source"],)).fetchall())
    assert any("author:u:700000002" in m for m in matched)
    assert any("forwarded_from:c:1300000077" in m for m in matched)


def test_a_poisoned_capture_record_skips_its_message_and_the_cursor_moves_on(conn, world):
    """commit_item runs inside the item's savepoint: a CHECK the capture
    record fails rolls back the message AND its document, the run names it,
    and the cursor still moves past it."""
    from noctornal_api.telegram import TelegramAdapter

    class Poisoned(TelegramAdapter):
        def _item(self, m, chat, persona_uid):
            item = super()._item(m, chat, persona_uid)
            if item is not None and m.message_id == 2:
                item.meta["telegram_message"]["sender_handle_at_capture"] = "n" * 300
            return item

    from noctornal_api.collection import CollectionService, RssAdapter

    fx = tp.fixture_for(world["chat"]["spec"], world["uid"], tp.messages(1, 3))
    adapter = Poisoned(tf.FakeFactory(fx), sleep=tf._no_sleep)
    result = CollectionService(conn, {"rss": RssAdapter(), "telegram": adapter},
                               sleep=lambda _s: None).run_once(world["source"],
                                                               actor_id=None)
    assert result.status == "PARTIAL" and result.items_new == 2
    # The foundation's ITEM_SKIPPED sentence; it redacts the id on its own,
    # and a bare 'c:<digits>/2' has the user:password shape its redactor
    # masks, so the id itself is not asserted.
    assert any("was skipped: the database refused it (CheckViolation)" in w
               for w in result.warnings), result.warnings
    stored = {r[0] for r in conn.execute(
        "SELECT external_id FROM collect.document WHERE source_id = %s",
        (world["source"],)).fetchall()}
    assert f"{world['chat']['durable_id']}/2" not in stored
    cursor = conn.execute("SELECT cursor FROM collect.collection_run WHERE id = %s",
                          (result.run_id,)).fetchone()[0]
    assert cursor["last_message_id"] == 3


def test_the_cursor_does_not_advance_when_the_persist_fails(conn, world):
    from noctornal_api.collection import CollectionService, RssAdapter
    from noctornal_api.telegram import TelegramAdapter

    fx = tp.fixture_for(world["chat"]["spec"], world["uid"], tp.messages(1, 3))
    adapter = TelegramAdapter(tf.FakeFactory(fx), sleep=tf._no_sleep)

    def broken(conn, **kw):
        raise RuntimeError("the chat table is gone")

    adapter.commit = broken
    svc = CollectionService(conn, {"rss": RssAdapter(), "telegram": adapter},
                            sleep=lambda _s: None)
    with pytest.raises(RuntimeError):
        svc.run_once(world["source"], actor_id=None)
    rows = conn.execute(
        "SELECT status::text, cursor FROM collect.collection_run WHERE source_id = %s",
        (world["source"],)).fetchall()
    assert [r[0] for r in rows] == ["FAILED"] and rows[0][1] == {}
    assert conn.execute("SELECT count(*) FROM collect.document WHERE source_id = %s",
                        (world["source"],)).fetchone()[0] == 0


# --- Telegram's answers, on the persona before the unlock ---------------------------

def test_flood_wait_puts_the_persona_on_a_machine_hold_and_the_run_is_rate_limited_not_failed(
        conn, world):
    from noctornal_api.telegram import TelegramFloodWait

    before = datetime.now(timezone.utc)
    result, _f, _a = _poll(conn, world, errors={"history": TelegramFloodWait(37)})
    hold, reason, _lock, _last = _persona_row(conn, world["persona"])
    failures, due = conn.execute(
        "SELECT consecutive_failures, next_due_at FROM collect.source WHERE id = %s",
        (world["source"],)).fetchone()
    assert result.status == "RATE_LIMITED" and failures == 0
    assert reason == "RATE_LIMITED"
    # The foundation's one margin, on Telegram's own 37 seconds.
    assert before + timedelta(seconds=37 * 1.1 + 5) <= hold
    assert hold <= datetime.now(timezone.utc) + timedelta(seconds=37 * 1.1 + 31)
    assert due >= hold - timedelta(seconds=1)


def test_an_abandoned_session_holds_the_persona_so_no_second_connection_starts(
        conn, world):
    from noctornal_api.collection import CollectionService, PersonaGate, RssAdapter
    from noctornal_api.telegram import TelegramAdapter

    class Stuck(tf.FakeTransport):
        async def open(self):
            time.sleep(2)
            return await super().open()

    fx = tp.fixture_for(world["chat"]["spec"], world["uid"], tp.messages(1, 2))
    adapter = TelegramAdapter(lambda s, r, f, *, proxy: Stuck(fx, secret=s, proxy=proxy),
                              sleep=tf._no_sleep, session_seconds=0.2,
                              backstop_seconds=0.3)
    result = CollectionService(conn, {"rss": RssAdapter(), "telegram": adapter},
                               sleep=lambda _s: None).run_once(world["source"],
                                                               actor_id=None)
    hold, reason, _lock, _last = _persona_row(conn, world["persona"])
    assert result.status == "FAILED" and reason == "ABANDONED"
    assert hold >= datetime.now(timezone.utc) + timedelta(seconds=800)
    from noctornal_api.collection import PersonaUnavailable

    with pytest.raises(PersonaUnavailable):
        PersonaGate(conn, world["persona"], actor_id=None, clearance=None,
                    purpose="x", source_id=None, need="PUBLIC_READ",
                    platform="TELEGRAM").check()


def test_a_revoked_session_locks_the_persona_and_notifies_managers(conn, world):
    from noctornal_api.telegram import TelegramSessionRevoked

    result, _f, _a = _poll(conn, world, errors={"open": TelegramSessionRevoked()})
    _h, _r, lock, _l = _persona_row(conn, world["persona"])
    assert result.status == "BLOCKED" and lock == "CREDENTIAL_REVOKED"
    notified = {r[0] for r in conn.execute(
        """SELECT recipient_id FROM notify.notification
            WHERE kind = 'PERSONA_SUSPENDED' AND object_id = %s""",
        (world["persona"],)).fetchall()}
    assert world["manager"] in notified


def test_a_duplicated_session_notifies_the_security_officer_urgently_and_names_no_chat(
        conn, world):
    from noctornal_api.telegram import TelegramSessionDuplicated

    _poll(conn, world, errors={"history": TelegramSessionDuplicated()})
    _h, _r, lock, _l = _persona_row(conn, world["persona"])
    assert lock == "CREDENTIAL_DUPLICATED"
    rows = conn.execute(
        """SELECT recipient_id, priority, body, summary FROM notify.notification
            WHERE kind = 'PERSONA_CREDENTIAL_ALERT' AND object_id = %s""",
        (world["persona"],)).fetchall()
    assert world["confirmer"] in {r[0] for r in rows}
    for _rid, priority, body, summary in rows:
        assert priority == 1
        assert world["chat"]["durable_id"] not in (body + summary)


def test_a_session_for_another_account_is_a_wrong_account_lock(conn, world):
    fx = tp.fixture_for(world["chat"]["spec"], "u:700000999", tp.messages(1, 1))
    result, _f, _a = _poll(conn, world, fx)
    assert result.status == "BLOCKED"
    assert _persona_row(conn, world["persona"])[2] == "WRONG_ACCOUNT"


def test_two_sources_on_one_persona_never_poll_at_once(conn, world):
    from noctornal_api.collection import CollectionBusy
    from noctornal_api.db import connect

    other = connect()
    try:
        other.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                      (f"collect.persona:{world['persona']}",))
        with pytest.raises(CollectionBusy, match="persona"):
            _poll(conn, world)
    finally:
        other.close()


def test_a_poll_outside_the_personas_active_hours_is_refused(conn, world):
    from noctornal_api.collection import PersonaResting

    now = datetime.now(timezone.utc)
    window = f"{(now + timedelta(hours=2)):%H:%M}-{(now + timedelta(hours=3)):%H:%M}"
    conn.execute("""UPDATE collect.collection_account
                       SET fingerprint_profile = fingerprint_profile
                           || jsonb_build_object('active_window_utc', %s::text)
                     WHERE id = %s""", (window, world["persona"]))
    with pytest.raises(PersonaResting, match="active hours"):
        _poll(conn, world)


# --- refusals before any run row -----------------------------------------------------

def test_a_source_above_the_ceiling_is_refused_and_an_unset_ceiling_refuses_everything(
        conn, world, monkeypatch):
    from noctornal_api.collection import SourceRefused

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "GREEN")
    with pytest.raises(SourceRefused, match="above the ceiling"):
        _poll(conn, world)
    monkeypatch.delenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING")
    with pytest.raises(SourceRefused, match="Telegram collection is off"):
        _poll(conn, world)
    assert conn.execute("SELECT count(*) FROM collect.collection_run WHERE source_id = %s",
                        (world["source"],)).fetchone()[0] == 0


@pytest.mark.parametrize("label", ["RED", "AMBER_STRICT"])
def test_red_and_amber_strict_ceilings_are_refused(conn, world, monkeypatch, label):
    from noctornal_api.collection import SourceRefused

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", label)
    with pytest.raises(SourceRefused, match="never leaves this platform"):
        _poll(conn, world)


def test_without_the_client_library_every_poll_refuses_and_says_so(conn, world, monkeypatch):
    from noctornal_api import telegram_wire
    from noctornal_api.collection import SourceRefused
    from noctornal_api.telegram import CLIENT_MISSING

    monkeypatch.setattr(telegram_wire, "library_version", lambda: None)
    with pytest.raises(SourceRefused) as caught:
        _poll(conn, world)
    assert str(caught.value) == CLIENT_MISSING


def test_without_an_egress_proxy_the_poll_is_refused_before_a_run_row(conn, world,
                                                                     monkeypatch):
    from noctornal_api import egress
    from noctornal_api.collection import SourceRefused
    from noctornal_api.telegram import NO_PROXY_SENTENCE

    monkeypatch.setattr(egress, "boundary", lambda env=None: egress.Boundary(
        "DIRECT", None, False, ""))
    with pytest.raises(SourceRefused) as caught:
        _poll(conn, world)
    assert str(caught.value) == NO_PROXY_SENTENCE


def test_a_refused_source_never_fills_the_cron_limit(conn, world):
    """A Telegram source with no chat record is refused before any run row,
    so it waits on a person and never takes a pass's slot."""
    from noctornal_api.collection import CollectionService

    refused = [h.source(conn, P, kind="TELEGRAM", parser="telegram", base_url=None,
                        persona=world["persona"]) for _ in range(3)]
    feed = h.source(conn, P, kind="RSS", parser="rss", base_url="https://feed.example.test/")
    svc = CollectionService(conn)
    due, held = svc.due_and_held()
    due_ids = {d["id"] for d in due}
    held_by = {s["id"]: s for s in held}
    assert feed in due_ids and not set(refused) & due_ids
    assert all(held_by[r]["reason"] == "REFUSED" for r in refused)
    assert "no chat record" in held_by[refused[0]]["sentence"]


def test_the_cron_does_not_start_a_telegram_poll_it_cannot_finish(conn, world):
    from noctornal_api.collection import CollectionService

    assert CollectionService(conn).poll_seconds(world["source"]) == 120.0


# --- a migration, the guards ------------------------------------------------------------

def test_a_migrated_group_deactivates_its_source_and_keeps_its_identity(conn, routes):
    recorder, confirmer, _m = _people(conn)
    pid, _e, uid = tp.persona(conn, P)
    ch = tp.chat(conn, P, persona_id=pid, resolved_by=recorder, peer_type="CHAT",
                 access_mode="MEMBER", member_since=True)
    h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[ch["source"]], scope="MEMBER_READ", member_ref="COVERT-7")
    target = f"c:{tp.rand_id()}"
    spec = dict(ch["spec"], migrated_to=target)
    result, _f, _a = _poll(conn, {"source": ch["source"], "chat": ch, "uid": uid},
                           tp.fixture_for(spec, uid, tp.messages(1, 1)))
    assert result.status == "BLOCKED" and target in result.blocked_reason
    row = conn.execute(
        """SELECT c.migrated_to, s.is_active, c.durable_id FROM collect.telegram_chat c
             JOIN collect.source s ON s.id = c.source_id WHERE c.source_id = %s""",
        (ch["source"],)).fetchone()
    assert row == (target, False, ch["durable_id"])
    assert conn.execute(
        """SELECT count(*) FROM audit.event WHERE action = 'TELEGRAM_CHAT_MIGRATED'
              AND object_id = %s AND actor_kind = 'SYSTEM'""",
        (ch["source"],)).fetchone()[0] == 1


def test_a_chat_identity_cannot_be_rewritten_deleted_or_truncated(conn, world):
    for sql in ("UPDATE collect.telegram_chat SET durable_id = 'c:999' WHERE source_id = %s",
                "UPDATE collect.telegram_chat SET username_at_resolve = 'other' "
                "WHERE source_id = %s",
                "DELETE FROM collect.telegram_chat WHERE source_id = %s"):
        with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
            conn.execute(sql, (world["source"],))
    with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
        conn.execute("TRUNCATE collect.telegram_chat CASCADE")


def test_a_public_chat_can_become_a_member_chat_but_never_back(conn, world):
    conn.execute("""UPDATE collect.telegram_chat
                       SET access_mode = 'MEMBER', provenance_class = 'PERSONA_PARTY'
                     WHERE source_id = %s""", (world["source"],))
    with pytest.raises(psycopg.errors.RaiseException, match="never back"), conn.transaction():
        conn.execute("""UPDATE collect.telegram_chat
                           SET access_mode = 'PUBLIC_READ', provenance_class = 'OPEN_GROUP'
                         WHERE source_id = %s""", (world["source"],))


def test_a_telegram_message_capture_record_cannot_be_rewritten_or_deleted(conn, world):
    _poll(conn, world)
    for sql in ("UPDATE collect.telegram_message SET message_id = 99 WHERE source_id = %s",
                "UPDATE collect.telegram_message SET sender_uid = NULL WHERE source_id = %s",
                "DELETE FROM collect.telegram_message WHERE source_id = %s"):
        with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
            conn.execute(sql, (world["source"],))
    with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
        conn.execute("TRUNCATE collect.telegram_message")
    with pytest.raises(psycopg.errors.ForeignKeyViolation), conn.transaction():
        conn.execute("DELETE FROM collect.document WHERE source_id = %s",
                     (world["source"],))


def test_the_runtime_role_cannot_delete_either_table(conn):
    from noctornal_api.db import connect  # noqa: F401 - the role is 0060's

    role = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_app'").fetchone()
    if role is None:
        pytest.skip("this database has no noctornal_app role (0060 notes why)")
    for table in ("collect.telegram_chat", "collect.telegram_message"):
        assert conn.execute("SELECT has_table_privilege('noctornal_app', %s, 'DELETE')",
                            (table,)).fetchone()[0] is False


def test_a_member_chat_the_persona_left_is_blocked_and_its_membership_cleared(conn, routes):
    """A member chat whose persona has left is not read as a member, and
    what was seen of its membership is cleared."""
    recorder, confirmer, _m = _people(conn)
    pid, _e, uid = tp.persona(conn, P)
    ch = tp.chat(conn, P, persona_id=pid, resolved_by=recorder, access_mode="MEMBER",
                 member_since=True)
    h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[ch["source"]], scope="MEMBER_READ", member_ref="COVERT-4")
    spec = dict(ch["spec"], is_member=False)
    result, _f, _a = _poll(conn, {"source": ch["source"], "chat": ch, "uid": uid},
                           tp.fixture_for(spec, uid, tp.messages(1, 2)))
    assert result.status == "BLOCKED" and "no longer a member" in result.blocked_reason
    member = conn.execute("SELECT member_since_observed FROM collect.telegram_chat "
                          "WHERE source_id = %s", (ch["source"],)).fetchone()[0]
    assert member is None
    assert conn.execute("SELECT count(*) FROM collect.document WHERE source_id = %s",
                        (ch["source"],)).fetchone()[0] == 0
