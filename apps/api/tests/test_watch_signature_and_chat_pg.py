"""F47 (docs/17, 2026-10-02): watches match a forum post's signature, and can
target a Telegram chat as such.

A post's signature is kept beside it (`collect.forum_post.signature_text`),
not in its text, so a watch on a contact address did not fire on a signature
that carried it. It does now, and its reasons say so
(`signature_keyword:`, `signature_selector:`, `signature_regex:`).

A watch of target kind TELEGRAM_CHAT names its chat by the typed id in
`target_ref`. It fires only on a message collected from that chat, leads its
reasons with `chat:<id>`, and with no term of any kind fires on every message
there. One that names another chat, or sits on a source that reads no Telegram
chat, matches nothing and says so in the run. Migration 0130 holds the
reference to a typed chat id for that kind and no other.

The watch tables are under row-level security (0124): the poll reads and
writes them as the COLLECTION system purpose, and the last tests here prove
the new reads and writes work on that connection and not on the request
role's. DATABASE_URL-gated; forum rows `f47f-`, Telegram `f47t-`, RLS
`f47r-`.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import date
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

import collection_helpers as h
import forum_helpers as fh
import rls_support as s
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PF = "f47f-"
PT = "f47t-"
PR = "f47r-"
SIG_TERM = "sig@xmpp.example.test"
BODY_TERM = "own@xmpp.example.test"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


# --- fixtures -------------------------------------------------------------------------

@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_FORUM_ALLOW_DIRECT", "1")
    monkeypatch.delenv("NOCTORNAL_EGRESS_PROXY_URL", raising=False)
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PF}%')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
    h.teardown(c, PF)
    h.retire_users(c, PF)
    c.close()


@pytest.fixture
def tconn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    tf.guard_sockets(monkeypatch)
    c = connect()
    yield c
    tp.teardown(c, PT)
    h.retire_users(c, PT)
    c.close()


@pytest.fixture
def routes(monkeypatch):
    return tf.patch_routes(monkeypatch)


def _forum(conn):
    """Two people, an exit, an XenForo thread source and a confirmed
    persona-less authority over it (test_forum_collection_pg's world)."""
    recorder, _ = h.user(conn, PF, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, PF, roles=("SECURITY_OFFICER",))
    egress = h.egress_profile(conn, PF)
    source = h.source(conn, PF, kind="XENFORO", parser="xenforo", base_url=fh.XF_THREAD,
                      egress=egress, max_rps=999)
    h.authority(conn, recorder=recorder, confirmer=confirmer, source_ids=[source],
                adapters=fh.registry())
    return {"owner": recorder, "source": source}


def _forum_poll(conn, world):
    from noctornal_api.collection import CollectionService
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    return CollectionService(conn, fh.registry(), fetcher=fh.xf_thread_site(),
                             raw_store=InMemoryDocumentRawStorage(),
                             sleep=lambda _s: None).run_once(world["source"], actor_id=None)


def _case(conn, owner):
    from noctornal_api.cases import CaseService

    return CaseService(conn).create(
        code=f"OP-F47-{uuid4().hex[:6]}", title="watch targets", legal_basis="order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner)


def _watch(conn, source, owner, *, case=None, kind="THREAD", ref="thread:1234", keywords=None,
           selectors=None, regexes=None, suppress=0, name=None):
    return conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref, keywords,
                selector_watch, regexes, owner_user_id, suppress_window_s)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (case, source, name or f"{PF}{uuid4().hex[:6]}", kind, ref, keywords, selectors,
         regexes, owner, suppress)).fetchone()[0]


def _hits(conn, watch):
    """{external_id: matched_on} of one watch's hits."""
    return {r[0]: r[1] for r in conn.execute(
        """SELECT d.external_id, h.matched_on FROM collect.watch_hit h
             JOIN collect.document d ON d.id = h.document_id
            WHERE h.watch_id = %s""", (watch,)).fetchall()}


def _posts_whose_signature_says(conn, source, term):
    return {r[0] for r in conn.execute(
        """SELECT d.external_id FROM collect.forum_post fp
             JOIN collect.document d ON d.id = fp.document_id
            WHERE d.source_id = %s AND fp.signature_text ILIKE %s""",
        (source, f"%{term}%")).fetchall()}


# --- a forum post's signature ------------------------------------------------------------

def test_a_watch_fires_on_a_signature_that_carries_its_term_and_says_so(conn):
    w = _forum(conn)
    watch = _watch(conn, w["source"], w["owner"], keywords=[SIG_TERM])
    result = _forum_poll(conn, w)
    assert result.status == "OK", (result.error, result.warnings)
    signed = _posts_whose_signature_says(conn, w["source"], SIG_TERM)
    assert signed, "the fixture thread carries signed posts"
    hits = _hits(conn, watch)
    assert set(hits) == signed and result.watch_hits == len(signed)
    assert all(m == [f"signature_keyword:{SIG_TERM}"] for m in hits.values())
    body_has_it = conn.execute(
        "SELECT count(*) FROM collect.document WHERE source_id = %s AND body_text ILIKE %s",
        (w["source"], f"%{SIG_TERM}%")).fetchone()[0]
    assert body_has_it == 0, "the term is in no post's text: it is the signature that fired"


def test_a_selector_and_a_pattern_match_the_signature_too(conn):
    w = _forum(conn)
    selector = _watch(conn, w["source"], w["owner"], selectors=[SIG_TERM])
    pattern = _watch(conn, w["source"], w["owner"], regexes=[r"sig@xmpp\.example\.test"])
    _forum_poll(conn, w)
    signed = _posts_whose_signature_says(conn, w["source"], SIG_TERM)
    assert {m for ms in _hits(conn, selector).values() for m in ms} == {
        f"signature_selector:{SIG_TERM}"}
    assert {m for ms in _hits(conn, pattern).values() for m in ms} == {
        r"signature_regex:sig@xmpp\.example\.test"}
    assert set(_hits(conn, selector)) == set(_hits(conn, pattern)) == signed


def test_a_term_in_the_text_and_one_in_the_signature_both_say_where_they_were_found(conn):
    w = _forum(conn)
    watch = _watch(conn, w["source"], w["owner"], keywords=[BODY_TERM, SIG_TERM])
    _forum_poll(conn, w)
    hits = _hits(conn, watch)
    assert hits["post:1001"] == [f"keyword:{BODY_TERM}", f"signature_keyword:{SIG_TERM}"]


def test_a_term_only_in_the_text_is_reported_as_it_always_was(conn):
    w = _forum(conn)
    watch = _watch(conn, w["source"], w["owner"], keywords=[BODY_TERM])
    _forum_poll(conn, w)
    hits = _hits(conn, watch)
    assert hits and all(m == [f"keyword:{BODY_TERM}"] for m in hits.values())


def test_a_watch_with_no_match_in_either_raises_nothing(conn):
    w = _forum(conn)
    watch = _watch(conn, w["source"], w["owner"], keywords=["nowhere-in-the-thread-1234"],
                   regexes=["zz[0-9]{9}qq"])
    result = _forum_poll(conn, w)
    assert _hits(conn, watch) == {} and result.watch_hits == 0


def test_a_broken_pattern_is_still_reported_once_and_does_not_stop_the_signature_match(conn):
    w = _forum(conn)
    broken = _watch(conn, w["source"], w["owner"], regexes=["[unclosed"])
    fine = _watch(conn, w["source"], w["owner"], keywords=[SIG_TERM])
    result = _forum_poll(conn, w)
    assert _hits(conn, broken) == {} and _hits(conn, fine)
    assert sum("will not compile" in text for text in result.warnings) == 1


def test_the_signature_hit_is_listed_for_the_case_with_its_reason(conn):
    from noctornal_api.collection import CollectionService

    w = _forum(conn)
    case = _case(conn, w["owner"])
    _watch(conn, w["source"], w["owner"], case=case, keywords=[SIG_TERM], name=f"{PF}listed")
    _forum_poll(conn, w)
    rows = CollectionService(conn).watch_hits(case, clearance="RED")
    assert rows and all(r["matched_on"] == [f"signature_keyword:{SIG_TERM}"] for r in rows)
    assert all(r["watch_name"] == f"{PF}listed" for r in rows)


def test_an_item_with_no_forum_side_or_a_non_text_signature_matches_as_before(conn):
    from noctornal_api.collection import CollectionService, FetchResult, Item

    recorder, _ = h.user(conn, PF, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, PF, roles=("SECURITY_OFFICER",))
    stub = h.StubAuthorityAdapter()
    source = h.source(conn, PF, egress=h.egress_profile(conn, PF))
    h.authority(conn, recorder=recorder, confirmer=confirmer, source_ids=[source],
                adapters=h.adapters(stub))
    watch = _watch(conn, source, recorder, keywords=["needle"])
    stub.produce = lambda _ctx: FetchResult(items=[
        Item(external_id="post:1", body="needle in the text"),
        Item(external_id="post:2", body="quiet", meta={"forum": {"signature": None}}),
        Item(external_id="post:3", body="quiet", meta={"forum": {"signature": 7}}),
        Item(external_id="post:4", body="quiet", meta={"forum": "not a dict"}),
        Item(external_id="post:5", body="quiet", meta={"forum": {"signature": "a needle"}}),
    ], http_status=200)
    result = CollectionService(conn, h.adapters(stub)).run_once(source, actor_id=None)
    assert result.status == "OK"
    assert _hits(conn, watch) == {"post:1": ["keyword:needle"],
                                  "post:5": ["signature_keyword:needle"]}


# --- a Telegram chat as the target ------------------------------------------------------

@pytest.fixture
def world(tconn, routes):
    recorder, _ = h.user(tconn, PT, roles=("COLLECTOR",))
    confirmer, _ = h.user(tconn, PT, roles=("SECURITY_OFFICER",))
    pid, egress, uid = tp.persona(tconn, PT)
    ch = tp.chat(tconn, PT, persona_id=pid, resolved_by=recorder)
    h.authority(tconn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[ch["source"]])
    return {"owner": recorder, "persona": pid, "uid": uid, "source": ch["source"],
            "chat": ch}


def _tg_poll(conn, world, messages):
    from noctornal_api.collection import CollectionService, RssAdapter
    from noctornal_api.telegram import TelegramAdapter

    fx = tp.fixture_for(world["chat"]["spec"], world["uid"], messages)
    adapter = TelegramAdapter(tf.FakeFactory(fx), sleep=tf._no_sleep)
    svc = CollectionService(conn, {"rss": RssAdapter(), "telegram": adapter},
                            sleep=lambda _s: None)
    return svc.run_once(world["source"], actor_id=None)


def _say(first, *texts):
    return [{"id": first + i, "date": f"2026-09-24T10:0{i}:00+00:00", "text": text,
             "from": {"type": "user", "id": 700000010 + i}}
            for i, text in enumerate(texts)]


def _chat_watch(conn, world, ref=None, **kw):
    return _watch(conn, world["source"], world["owner"], kind="TELEGRAM_CHAT",
                  ref=ref or world["chat"]["durable_id"], name=f"{PT}{uuid4().hex[:6]}", **kw)


def test_a_chat_watch_with_terms_fires_on_them_and_leads_with_the_chat(tconn, world):
    chat = world["chat"]["durable_id"]
    watch = _chat_watch(tconn, world, keywords=["alpha"])
    result = _tg_poll(tconn, world, _say(1, "alpha news", "beta news"))
    assert result.status == "OK" and result.watch_hits == 1
    assert list(_hits(tconn, watch).values()) == [[f"chat:{chat}", "keyword:alpha"]]


def test_a_chat_watch_with_no_term_is_a_watch_on_the_chat_and_fires_on_every_message(
        tconn, world):
    chat = world["chat"]["durable_id"]
    watch = _chat_watch(tconn, world)
    result = _tg_poll(tconn, world, _say(1, "one", "two", "three"))
    assert result.watch_hits == 3
    assert list(_hits(tconn, watch).values()) == [[f"chat:{chat}"]] * 3


def test_a_chat_watch_with_no_term_is_thinned_by_its_suppression_window(tconn, world):
    watch = _chat_watch(tconn, world, suppress=3600)
    result = _tg_poll(tconn, world, _say(1, "one", "two", "three"))
    assert result.watch_hits == 1 and len(_hits(tconn, watch)) == 1


def test_a_chat_watch_on_another_chat_matches_nothing_and_the_run_says_so(tconn, world):
    watch = _chat_watch(tconn, world, ref="c:424242", keywords=["alpha"])
    result = _tg_poll(tconn, world, _say(1, "alpha news", "alpha again"))
    assert _hits(tconn, watch) == {} and result.watch_hits == 0
    assert result.status == "PARTIAL"
    assert f"watch {watch} targets Telegram chat c:424242 and this source reads another " \
           f"chat, so it matches nothing here." in result.warnings
    error_class = tconn.execute("SELECT error_class FROM collect.collection_run WHERE id = %s",
                                (result.run_id,)).fetchone()[0]
    assert error_class == "WatchPatternError"
    assert sum(str(watch) in text for text in result.warnings) == 1, "once per run"


def test_a_chat_watch_on_a_source_that_reads_no_telegram_chat_says_so(conn):
    w = _forum(conn)
    watch = _watch(conn, w["source"], w["owner"], kind="TELEGRAM_CHAT", ref="c:424242",
                   keywords=[BODY_TERM])
    result = _forum_poll(conn, w)
    assert _hits(conn, watch) == {}
    assert f"watch {watch} targets Telegram chat c:424242 and this source reads no " \
           f"Telegram chat, so it matches nothing here." in result.warnings


def test_a_chat_watch_still_matches_the_typed_ids_a_message_carries(tconn, world):
    chat = world["chat"]["durable_id"]
    watch = _chat_watch(tconn, world, selectors=["u:700000010"], suppress=0)
    result = _tg_poll(tconn, world, _say(1, "hello", "bye"))
    assert result.watch_hits == 1
    assert list(_hits(tconn, watch).values()) == [[f"chat:{chat}", "author:u:700000010"]]


def test_the_other_kinds_are_unchanged(tconn, world):
    """No term, no match, for every kind but the chat's; and a kind that is not
    TELEGRAM_CHAT never grows a `chat:` reason."""
    plain = _watch(tconn, world["source"], world["owner"], kind="BOARD", ref="b",
                   name=f"{PT}plain")
    termed = _watch(tconn, world["source"], world["owner"], kind="FORUM", ref="b",
                    keywords=["alpha"], name=f"{PT}termed")
    result = _tg_poll(tconn, world, _say(1, "alpha news", "beta"))
    assert _hits(tconn, plain) == {}
    assert list(_hits(tconn, termed).values()) == [["keyword:alpha"]]
    assert result.status == "OK"


# --- the reference a chat watch holds (migration 0130) ------------------------------------

def _insert_watch(conn, source, owner, kind, ref):
    conn.execute(
        """INSERT INTO collect.watch (source_id, name, target_kind, target_ref, owner_user_id)
           VALUES (%s, %s, %s, %s, %s)""", (source, f"{PF}chk", kind, ref, owner))


def test_a_telegram_chat_watch_must_name_its_chat_by_the_typed_id(conn):
    w = _forum(conn)
    for ref in ("c:1", "g:77", "c:" + "9" * 20):
        _insert_watch(conn, w["source"], w["owner"], "TELEGRAM_CHAT", ref)
    for ref in ("@somechat", "u:5", "C:5", "c:05", "c:0", "5", "-1001", "c:", "c:1/2",
                "c:" + "9" * 21, "c:1 ", "t.me/somechat"):
        with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
            _insert_watch(conn, w["source"], w["owner"], "TELEGRAM_CHAT", ref)


def test_the_kind_is_matched_exactly_and_another_case_is_refused_not_stored(conn):
    w = _forum(conn)
    for kind in ("telegram_chat", "Telegram_Chat"):
        with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
            _insert_watch(conn, w["source"], w["owner"], kind, "c:1")


def test_every_other_kind_keeps_the_free_text_it_had(conn):
    w = _forum(conn)
    for kind, ref in (("BOARD", "https://forum.test/b/1"), ("FORUM", "@anything"),
                      ("KEYWORD", "x"), ("TELEGRAM_CHANNEL", "@somechannel")):
        _insert_watch(conn, w["source"], w["owner"], kind, ref)


def test_an_update_cannot_make_a_chat_watch_name_a_displayed_handle(conn):
    w = _forum(conn)
    chat = _watch(conn, w["source"], w["owner"], kind="TELEGRAM_CHAT", ref="c:1")
    other = _watch(conn, w["source"], w["owner"], kind="FORUM", ref="@somebody")
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE collect.watch SET target_ref = '@renamed' WHERE id = %s", (chat,))
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE collect.watch SET target_kind = 'TELEGRAM_CHAT' WHERE id = %s",
                     (other,))
    conn.execute("UPDATE collect.watch SET target_ref = 'g:77' WHERE id = %s", (chat,))


def test_the_migrations_pattern_is_the_adapters_chat_pattern():
    from noctornal_api.telegram import CHAT_PATTERN

    assert _migration("0130").CHAT_ID == CHAT_PATTERN[1:-1]


class _RollBack(Exception):
    pass


def _migration(stem):
    path = next(VERSIONS.glob(f"{stem}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _has_constraint(conn) -> bool:
    return conn.execute(
        """SELECT EXISTS (SELECT 1 FROM pg_constraint
                           WHERE conname = 'watch_telegram_chat_typed'
                             AND conrelid = 'collect.watch'::regclass)""").fetchone()[0]


def test_0130_goes_down_refuses_over_a_bad_row_and_comes_back_up(conn):
    """Upgrade, downgrade, upgrade, inside a transaction that is rolled back so
    the database the rest of the suite uses never sees the intermediate state."""
    w = _forum(conn)
    m = _migration("0130")
    m.run = lambda sql: conn.execute(sql)
    assert _has_constraint(conn), "the clone is at head"
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        assert not _has_constraint(conn)
        # Without the constraint a bad reference can be written, as before.
        _insert_watch(conn, w["source"], w["owner"], "TELEGRAM_CHAT", "@bychance")
        _insert_watch(conn, w["source"], w["owner"], "telegram_chat", "c:1")
        with pytest.raises(psycopg.errors.RaiseException) as caught, conn.transaction():
            m.upgrade()
        text = str(caught.value)
        assert "refusing to upgrade 0130: 2 watches target a Telegram chat" in text
        assert "typed chat id (c:<id> or g:<id>)" in text and "Correct each by hand" in text
        assert "(es)" not in text and "—" not in text and " -- " not in text
        conn.execute("DELETE FROM collect.watch WHERE name = %s", (f"{PF}chk",))
        m.upgrade()
        assert _has_constraint(conn)
        with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
            _insert_watch(conn, w["source"], w["owner"], "TELEGRAM_CHAT", "@bychance")
        raise _RollBack
    assert _has_constraint(conn), "the rolled-back round trip left the database at head"


def test_0130_refuses_a_single_row_in_the_singular(conn):
    w = _forum(conn)
    m = _migration("0130")
    m.run = lambda sql: conn.execute(sql)
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        _insert_watch(conn, w["source"], w["owner"], "TELEGRAM_CHAT", "@bychance")
        with pytest.raises(psycopg.errors.RaiseException) as caught, conn.transaction():
            m.upgrade()
        assert "refusing to upgrade 0130: 1 watch targets a Telegram chat" in str(caught.value)
        assert "Correct it by hand" in str(caught.value)
        raise _RollBack


# --- the right connection: the watch tables are under row-level security ------------------

@s.GATED
def test_the_matcher_reads_and_writes_the_watch_tables_as_the_collection_purpose(
        monkeypatch):
    """`collect.watch` is under policy (0124). A reader bound as an analyst sees
    only the watches of cases they may read, so a poll on that connection would
    miss a chat watch or a signature watch of any other case. The poll runs as
    the COLLECTION system purpose, which sees them all, reads the target kind and
    reference with them and writes the hits, whatever the requester may read."""
    from noctornal_api.collection import CollectionService, FetchResult, Item
    from noctornal_api.db import ASSUME_ROLE_ENV, SystemPurpose, system_connection

    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    owner = s.owner_conn()
    try:
        boss = s.user(owner, "RED", prefix=PR)
        analyst = s.user(owner, "AMBER", prefix=PR)
        mine, theirs = s.case(owner, boss), s.case(owner, boss)
        s.assign(owner, mine, analyst)
        source = owner.execute(
            """INSERT INTO collect.source (kind, name, base_url, default_reliability,
                                           classification, parser_key)
               VALUES ('RSS', %s, 'https://feed.example.test/rss', 'F', 'AMBER', 'rss')
               RETURNING id""",
            (f"{PR}{uuid4().hex[:8]}",)).fetchone()[0]
        visible = _watch(owner, source, boss, case=mine, keywords=["needle"],
                         name=f"{PR}visible")
        hidden_signature = _watch(owner, source, boss, case=theirs, keywords=["needle"],
                                  name=f"{PR}hidden-sig")
        hidden_chat = _watch(owner, source, boss, case=theirs, kind="TELEGRAM_CHAT",
                             ref="c:424242", name=f"{PR}hidden-chat")
        _, raw = s.session(owner, analyst)
        app = s.app_conn(raw)
        try:
            as_request = {r[0] for r in CollectionService(app)._watches(source)}
            assert as_request == {visible}, "the request role cannot see the other case's watches"
            with system_connection(SystemPurpose.COLLECTION, reuse=app) as sconn:
                rows = {r[0]: r for r in CollectionService(sconn)._watches(source)}
                assert set(rows) == {visible, hidden_signature, hidden_chat}
                assert rows[hidden_chat][7:] == ("TELEGRAM_CHAT", "c:424242"), (
                    "the kind and reference ride with the read")

                class Reads:
                    key, version = "rss", "f47"

                    def fetch(self, **kw):
                        return FetchResult(items=[Item(
                            external_id="g-1", body="quiet",
                            meta={"forum": {"signature": "a needle in a signature"}})],
                            http_status=200)

                result = CollectionService(sconn, {"rss": Reads()}).run_once(
                    source, actor_id=None)
            assert result.status == "PARTIAL", "the misaimed chat watch is reported"
            assert any(str(hidden_chat) in text for text in result.warnings)
            got = {w: owner.execute(
                "SELECT matched_on FROM collect.watch_hit WHERE watch_id = %s",
                (w,)).fetchall() for w in (visible, hidden_signature, hidden_chat)}
            assert got[visible] == [(["signature_keyword:needle"],)]
            assert got[hidden_signature] == [(["signature_keyword:needle"],)]
            assert got[hidden_chat] == []
        finally:
            app.close()
    finally:
        owner.execute(f"DELETE FROM collect.watch_hit WHERE watch_id IN "
                      f"(SELECT id FROM collect.watch WHERE name LIKE '{PR}%')")
        owner.execute(f"DELETE FROM collect.watch WHERE name LIKE '{PR}%'")
        owner.execute(f"DELETE FROM collect.document WHERE source_id IN "
                      f"(SELECT id FROM collect.source WHERE name LIKE '{PR}%')")
        owner.execute(f"""DELETE FROM collect.collection_run WHERE source_id IN
                          (SELECT id FROM collect.source WHERE name LIKE '{PR}%')""")
        owner.execute(f"DELETE FROM collect.source WHERE name LIKE '{PR}%'")
        s.cleanup(owner, PR)
        owner.close()


# --- what a purge keeps of a hit's reasons ------------------------------------------------

def test_a_purge_keeps_the_watchs_own_terms_and_scrubs_what_came_from_the_document(conn):
    """The reasons that are the watch's own configuration (a term, a chat it
    names) survive a purged document; the ones read from the document do not."""
    import hashlib
    from datetime import datetime, timedelta, timezone

    from noctornal_api.retention import RetentionService

    w = _forum(conn)
    owner = w["owner"]
    case = _case(conn, owner)
    watch = _watch(conn, w["source"], owner, case=case, keywords=["x"])
    doc = conn.execute(
        """INSERT INTO collect.document (source_id, external_id, body_text, content_sha256,
                                         retain_until, title, author_handle, author_uid,
                                         category)
           VALUES (%s, 'post:9', 'a body', %s, %s, 'a title', 'vendor_x', 'u:99',
                   'CHAT_EXPORT') RETURNING id""",
        (w["source"], hashlib.sha256(uuid4().bytes).digest(),
         datetime.now(timezone.utc) - timedelta(days=1))).fetchone()[0]
    conn.execute(
        """INSERT INTO collect.watch_hit (watch_id, document_id, matched_on)
           VALUES (%s, %s, %s)""",
        (watch, doc, '["chat:c:424242", "keyword:a", "signature_keyword:b", '
                     '"signature_selector:c", "signature_regex:d", '
                     '"author:u:99", "forwarded_from:c:5"]'))
    RetentionService(conn).purge_due(actor_id=owner, authority="retention schedule",
                                     dry_run=False)
    matched = conn.execute("SELECT matched_on FROM collect.watch_hit WHERE document_id = %s",
                           (doc,)).fetchone()[0]
    assert matched == ["chat:c:424242", "keyword:a", "signature_keyword:b",
                       "signature_selector:c", "signature_regex:d",
                       "author:[purged]", "forwarded_from:[purged]"]
