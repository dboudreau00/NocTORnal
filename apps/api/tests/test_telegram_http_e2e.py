"""Telegram chats and personas over HTTP, with a fake transport and no
network (roadmap F5.2 and F5.3, 2026-09-24).

Looking a chat up as a persona; the answers that must not tell a hidden
source from a missing one; the step-up on every binding change; the fixed
answer of each act's outcome; the membership acts that never join; the
readiness gate; and the Telegram lines in the collection routes (personas,
due, documents) and in the authority views. DATABASE_URL-gated.
"""
from __future__ import annotations

import os
import uuid

import pytest

import collection_helpers as h
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-tghttp-"
API = "/api/v1/collection"
TG = f"{API}/telegram"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    from noctornal_api.http.routers import collection as router

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    monkeypatch.setattr(router, "blocking_failures", lambda _c: [])
    tf.guard_sockets(monkeypatch)
    c = connect()
    yield c
    tp.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def routes(monkeypatch):
    return tf.patch_routes(monkeypatch)


class Api:
    """The test client with a swappable fake Telegram."""

    def __init__(self, client, app):
        self.client = client
        self.app = app
        self.factory = None

    def telegram(self, fx, **kw):
        from noctornal_api.http.routers import collection as router
        from noctornal_api.http.routers import collection_telegram as tgr
        from noctornal_api.collection import RssAdapter
        from noctornal_api.telegram import TelegramAdapter

        self.factory = tf.FakeFactory(fx, **kw)
        registry = {"rss": RssAdapter(),
                    "telegram": TelegramAdapter(self.factory, sleep=tf._no_sleep)}
        self.app.dependency_overrides[tgr.get_transport_factory] = lambda: self.factory
        self.app.dependency_overrides[router.get_adapters] = lambda: registry
        return self.factory


@pytest.fixture
def api(conn, routes):
    client, app = h.client()
    return Api(client, app)


def _caller(conn, *, clearance="RED", roles=("COLLECTOR",), fresh=True):
    uid, email = h.user(conn, P, clearance=clearance, roles=roles)
    return uid, h.auth(h.session(conn, email, fresh=fresh))


@pytest.fixture
def world(conn, routes):
    recorder = h.user(conn, P, roles=("COLLECTOR",))[0]
    confirmer, confirmer_email = h.user(conn, P, roles=("SECURITY_OFFICER",))
    pid, egress, uid = tp.persona(conn, P)
    # The persona's own authority with no source: its acts, and no read.
    view = h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                       source_ids=[])
    caller, hdr = _caller(conn)
    return {"recorder": recorder, "confirmer": confirmer, "persona": pid,
            "egress": egress, "uid": uid, "caller": caller, "hdr": hdr,
            "authority": view["id"],
            "officer": h.auth(h.session(conn, confirmer_email))}


def _chat_spec(**over):
    spec = {"peer_type": "CHANNEL", "peer_id": tp.rand_id(), "access_hash": 991,
            "username": f"tg{uuid.uuid4().hex[:10]}", "title": "Example chat",
            "is_member": False}
    spec.update(over)
    return spec


def _body(world, ref, **over):
    body = {"persona_id": str(world["persona"]), "ref": ref, "name": f"{P}chat",
            "classification": "AMBER", "access_mode": "PUBLIC_READ"}
    body.update(over)
    return body


def _create(api, world, spec=None, *, ref=None, **over):
    spec = spec or _chat_spec()
    fx = tp.fixture_for(spec, world["uid"])
    api.telegram(fx)
    ref = ref or f"@{spec['username']}"
    return api.client.post(f"{TG}/chats", headers=world["hdr"],
                           json=_body(world, ref, **over)), spec


# --- adding a chat --------------------------------------------------------------

def test_a_chat_is_looked_up_as_the_persona_and_added_as_its_source(conn, api, world):
    r, spec = _create(api, world)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["chat"]["durable_id"] == f"c:{spec['peer_id']}"
    assert body["chat"]["access_mode"] == "PUBLIC_READ"
    assert "confirms this chat" in body["next"]
    row = conn.execute(
        """SELECT s.kind::text, s.parser_key, s.base_url, s.collection_account_id,
                  s.parser_config, c.provenance_class, c.resolved_by,
                  c.access_hash_account_id
             FROM collect.source s JOIN collect.telegram_chat c ON c.source_id = s.id
            WHERE s.id = %s""", (body["source"]["id"],)).fetchone()
    assert row[:4] == ("TELEGRAM", "telegram", None, world["persona"])
    assert row[4] == {"access_mode": "PUBLIC_READ"} and row[5] == "OPEN_GROUP"
    assert row[6] == world["caller"] and row[7] == world["persona"]
    assert [m for m in api.factory.methods() if m != "close"] == ["open", "resolve_username"]
    assert api.factory.proxies[0]["username"].endswith(f"~act.{world['persona']}")
    audits = {r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s",
        (uuid.UUID(body["source"]["id"]),)).fetchall()}
    assert {"SOURCE_CREATED", "TELEGRAM_CHAT_RESOLVED"} <= audits


def test_a_bare_positive_and_an_invite_link_are_refused_before_telegram(conn, api, world):
    api.telegram(tp.fixture_for(_chat_spec(), world["uid"]))
    for ref, words in (("1300000001", "ambiguous"), ("https://t.me/+AbCdEf123", "invite link")):
        r = api.client.post(f"{TG}/chats", headers=world["hdr"], json=_body(world, ref))
        assert r.status_code == 400 and words in r.json()["detail"]
    assert api.factory.transports == []


def test_adding_a_chat_needs_a_fresh_second_factor_and_writes_nothing(conn, api, world):
    _uid, stale = _caller(conn, fresh=False)
    spec = _chat_spec()
    api.telegram(tp.fixture_for(spec, world["uid"]))
    r = api.client.post(f"{TG}/chats", headers=stale,
                        json=_body(world, f"@{spec['username']}"))
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
    assert api.factory.transports == []
    assert conn.execute("SELECT count(*) FROM collect.telegram_chat WHERE durable_id = %s",
                        (f"c:{spec['peer_id']}",)).fetchone()[0] == 0


def test_an_existing_visible_chat_is_named_and_a_hidden_one_answers_like_an_unresolvable_one(
        conn, api, world):
    r, spec = _create(api, world)
    assert r.status_code == 201
    again, _ = _create(api, world, spec, name=f"{P}again")
    assert again.status_code == 409 and f"{P}chat" in again.json()["detail"]
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                 (r.json()["source"]["id"],))
    amber_uid, amber = _caller(conn, clearance="AMBER")
    hidden_world = dict(world, hdr=amber)
    other = tp.persona(conn, P)
    h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                persona_id=other[0], source_ids=[])
    hidden_world.update(persona=other[0], uid=other[2])
    hidden, _ = _create(api, hidden_world, spec, name=f"{P}hidden")
    missing, _ = _create(api, hidden_world, _chat_spec(),
                         ref="@nobodyhasthisname", name=f"{P}missing")
    assert hidden.status_code == missing.status_code == 422
    assert hidden.json() == missing.json()
    assert conn.execute(
        """SELECT count(*) FROM audit.event WHERE action = 'TELEGRAM_CHAT_DUPLICATE_HIDDEN'
              AND actor_id = %s""", (amber_uid,)).fetchone()[0] == 1


def test_a_persona_already_a_member_forces_a_member_chat(conn, api, world):
    r, _spec = _create(api, world, _chat_spec(is_member=True))
    assert r.status_code == 201, r.text
    assert r.json()["chat"]["access_mode"] == "MEMBER"
    assert "already a member" in r.json()["notice"]
    assert r.json()["chat"]["member_since_observed"] is not None


def test_resolve_by_id_writes_only_the_matched_chat(conn, api, world):
    spec = _chat_spec(peer_type="CHAT", access_hash=None, username=None, is_member=True)
    others = [_chat_spec() for _ in range(3)]
    fx = tp.fixture_for(spec, world["uid"], dialogs=others)
    api.telegram(fx)
    # Reading the persona's own conversation list needs its member scope.
    h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                persona_id=world["persona"], source_ids=[], scope="MEMBER_READ",
                member_ref="COVERT-2026-3")
    r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                        json=_body(world, f"-{spec['peer_id']}", access_mode="MEMBER"))
    assert r.status_code == 201, r.text
    assert "find_dialog" in api.factory.methods()
    written = conn.execute("SELECT durable_id FROM collect.telegram_chat "
                           "WHERE durable_id = ANY(%s)",
                           ([f"g:{spec['peer_id']}"] + [f"c:{o['peer_id']}" for o in others],)
                           ).fetchall()
    assert [w[0] for w in written] == [f"g:{spec['peer_id']}"]


# --- the outcomes of an act ------------------------------------------------------

@pytest.mark.parametrize("error, status, words", [
    ("flood", 409, "asked this persona to wait until"),
    ("revoked", 409, "locked until a new credential is enrolled"),
    ("egress", 503, "The egress proxy refused the connection to Telegram"),
    ("transport", 502, "Telegram could not be reached. Nothing was changed."),
    ("unreachable", 422, "could not be added through this persona"),
])
def test_each_act_outcome_answers_its_fixed_status(conn, api, world, error, status, words):
    from noctornal_api import telegram

    errors = {"flood": telegram.TelegramFloodWait(30),
              "revoked": telegram.TelegramSessionRevoked(),
              "egress": telegram.TelegramEgressRefused(),
              "transport": telegram.TelegramTransportFailed("TimedOutError"),
              "unreachable": telegram.TelegramChatUnreachable()}
    spec = _chat_spec()
    api.telegram(tp.fixture_for(spec, world["uid"]),
                 errors={"resolve_username": errors[error]})
    r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                        json=_body(world, f"@{spec['username']}"))
    assert r.status_code == status and words in r.json()["detail"], r.text
    assert "TimedOutError" not in r.text


def test_a_rate_limit_during_chat_lookup_holds_the_persona(conn, api, world):
    from noctornal_api import telegram

    spec = _chat_spec()
    api.telegram(tp.fixture_for(spec, world["uid"]),
                 errors={"resolve_username": telegram.TelegramFloodWait(40)})
    r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                        json=_body(world, f"@{spec['username']}"))
    assert r.status_code == 409 and "UTC" in r.json()["detail"]
    reason = conn.execute("SELECT machine_hold_reason FROM collect.collection_account "
                          "WHERE id = %s", (world["persona"],)).fetchone()[0]
    assert reason == "RATE_LIMITED"


def test_an_abandoned_act_holds_the_persona_before_the_unlock(conn, api, world, monkeypatch):
    from noctornal_api import telegram, telegram_service

    real = telegram.run_blocking

    def quick(factory, budget, *, backstop_s=telegram.BACKSTOP_SECONDS):
        return real(factory, 0.1, backstop_s=0.2)

    monkeypatch.setattr(telegram_service, "run_blocking", quick)

    class Stuck(tf.FakeTransport):
        async def open(self):
            import time
            time.sleep(1.5)
            return await super().open()

    spec = _chat_spec()
    fx = tp.fixture_for(spec, world["uid"])
    api.telegram(fx)
    api.app.dependency_overrides[
        __import__("noctornal_api.http.routers.collection_telegram",
                   fromlist=["x"]).get_transport_factory] = (
        lambda: lambda s, r, f, *, proxy: Stuck(fx, secret=s, proxy=proxy))
    r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                        json=_body(world, f"@{spec['username']}"))
    assert r.status_code == 504 and "rests for 15 minutes" in r.json()["detail"], r.text
    reason = conn.execute("SELECT machine_hold_reason FROM collect.collection_account "
                          "WHERE id = %s", (world["persona"],)).fetchone()[0]
    assert reason == "ABANDONED"


# --- joins and membership ---------------------------------------------------------

def _member_chat(conn, api, world, *, username=True, peer_type="MEGAGROUP",
                 confirm_member=True, member_since=False):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"],
                 access_mode="MEMBER", peer_type=peer_type, member_since=member_since,
                 username="auto" if username else None,
                 access_hash=None if peer_type == "CHAT" else 55)
    if confirm_member:
        h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                    persona_id=world["persona"], source_ids=[ch["source"]],
                    scope="MEMBER_READ", member_ref="COVERT-2026-5")
    return ch


def test_join_needs_the_overt_act_acknowledged_a_member_target_and_a_fresh_factor(
        conn, api, world):
    unconfirmed = _member_chat(conn, api, world, confirm_member=False)
    api.telegram(tp.fixture_for(unconfirmed["spec"], world["uid"]), allow_join=True)
    url = f"{TG}/chats/{unconfirmed['source']}/join"
    note = {"note": "joining for the operation"}
    assert api.client.post(url, headers=world["hdr"], json=note).status_code == 422
    r = api.client.post(url, headers=world["hdr"], json={**note, "acknowledge_overt": True})
    assert r.status_code == 409, r.text
    assert "join" not in api.factory.methods()
    _u, stale = _caller(conn, fresh=False)
    ch = _member_chat(conn, api, world)
    r = api.client.post(f"{TG}/chats/{ch['source']}/join", headers=stale,
                        json={**note, "acknowledge_overt": True})
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
    api.telegram(tp.fixture_for(ch["spec"], world["uid"]), allow_join=True)
    r = api.client.post(f"{TG}/chats/{ch['source']}/join", headers=world["hdr"],
                        json={**note, "acknowledge_overt": True})
    assert r.status_code == 200, r.text
    assert "recent actions log" in r.json()["notice"]
    assert api.factory.methods().count("join") == 1
    joined = conn.execute("SELECT member_since_observed, joined_by FROM collect.telegram_chat "
                          "WHERE source_id = %s", (ch["source"],)).fetchone()
    assert joined[0] is not None and joined[1] == world["caller"]


def test_a_membership_check_never_joins(conn, api, world):
    ch = _member_chat(conn, api, world, username=False, peer_type="CHAT")
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    r = api.client.post(f"{TG}/chats/{ch['source']}/membership", headers=world["hdr"])
    assert r.status_code == 200 and r.json()["member"] is True, r.text
    assert "join" not in api.factory.methods()
    assert api.factory.proxies[-1]["username"].endswith(f"~act.{world['persona']}")


def test_a_marked_public_chat_is_readable_after_a_membership_check_with_no_join_request(
        conn, api, world):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"])
    h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                persona_id=world["persona"], source_ids=[ch["source"]],
                scope="MEMBER_READ", member_ref="COVERT-2026-8")
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    r = api.client.post(f"{TG}/chats/{ch['source']}/member", headers=world["hdr"],
                        json={"reason": "the persona joined on its phone"})
    assert r.status_code == 200 and r.json()["marked"] and r.json()["member"], r.text
    assert "join" not in api.factory.methods()
    row = conn.execute(
        """SELECT c.access_mode, c.member_since_observed IS NOT NULL, s.parser_config
             FROM collect.telegram_chat c JOIN collect.source s ON s.id = c.source_id
            WHERE c.source_id = %s""", (ch["source"],)).fetchone()
    assert row == ("MEMBER", True, {"access_mode": "MEMBER"})
    run = api.client.post(f"{API}/sources/{ch['source']}/run", headers=world["hdr"], json={})
    assert run.status_code == 200 and run.json()["status"] == "OK", run.text


def test_marking_without_a_member_authority_keeps_the_mark_and_answers_409(conn, api, world):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"])
    api.telegram(tp.fixture_for(ch["spec"], world["uid"]))
    r = api.client.post(f"{TG}/chats/{ch['source']}/member", headers=world["hdr"],
                        json={"reason": "it is a member chat now"})
    assert r.status_code == 409 and r.json()["detail"].startswith("The chat is now a member chat.")
    assert conn.execute("SELECT access_mode FROM collect.telegram_chat WHERE source_id = %s",
                        (ch["source"],)).fetchone()[0] == "MEMBER"


def test_a_rebound_basic_group_is_readable_again_without_a_join(conn, api, world):
    ch = _member_chat(conn, api, world, username=False, peer_type="CHAT", member_since=True)
    new_pid, _e, new_uid = tp.persona(conn, P)
    h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                persona_id=new_pid, source_ids=[], scope="MEMBER_READ",
                member_ref="COVERT-2026-6")
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), new_uid))
    r = api.client.post(f"{TG}/chats/{ch['source']}/persona", headers=world["hdr"],
                        json={"persona_id": str(new_pid), "reason": "the old one burnt"})
    assert r.status_code == 200, r.text
    assert "per account" in r.json()["notice"]
    row = conn.execute(
        """SELECT s.collection_account_id, s.cursor_reset_at IS NOT NULL,
                  c.member_since_observed IS NOT NULL, c.joined_by
             FROM collect.source s JOIN collect.telegram_chat c ON c.source_id = s.id
            WHERE s.id = %s""", (ch["source"],)).fetchone()
    assert row == (new_pid, True, True, None)
    assert "join" not in api.factory.methods()
    assert api.factory.proxies[-1]["username"].endswith(f"~act.{new_pid}")
    _u, stale = _caller(conn, fresh=False)
    r = api.client.post(f"{TG}/chats/{ch['source']}/persona", headers=stale,
                        json={"persona_id": str(world["persona"]), "reason": "back again"})
    assert r.status_code == 403


# --- labels -------------------------------------------------------------------------

def test_a_hidden_source_answers_like_a_missing_one_on_every_chat_route(conn, api, world):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"],
                 classification="RED")
    api.telegram(tp.fixture_for(ch["spec"], world["uid"]))
    _uid, amber = _caller(conn, clearance="AMBER")
    missing = uuid.uuid4()
    posts = (("join", {"acknowledge_overt": True, "note": "a long enough note"}),
             ("persona", {"persona_id": str(world["persona"]), "reason": "a reason"}),
             ("member", {"reason": "a reason"}), ("membership", None),
             ("deactivate", {"reason": "a reason"}), ("resume", {"reason": "a reason"}))
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter

    for path, body in posts:
        # A fresh meter per pair: the persona-act limit (burst 5) is not
        # what this test is about.
        api.app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
        a = api.client.post(f"{TG}/chats/{ch['source']}/{path}", headers=amber, json=body)
        b = api.client.post(f"{TG}/chats/{missing}/{path}", headers=amber, json=body)
        assert a.status_code == b.status_code == 404, (path, a.text, b.text)
        assert a.json() == b.json(), path
    listed = api.client.get(f"{TG}/chats", headers=amber).json()
    assert str(ch["source"]) not in {c["source_id"] for c in listed["chats"]}


def test_deactivate_and_resume_carry_no_persona_act_limit():
    from noctornal_api.http.routers import collection_telegram as tgr

    by_name = {r.name: r for r in tgr.router.routes}
    for name in ("stop_chat", "resume_chat"):
        deps = repr([d.call for d in by_name[name].dependant.dependencies])
        assert "persona_act" not in deps, name
    for name in ("create_chat", "join_chat", "rebind_chat", "mark_member_chat",
                 "check_membership"):
        route = by_name[name]
        closures = [getattr(d.call, "__closure__", None) or () for d in
                    route.dependant.dependencies]
        names = [c.cell_contents for cells in closures for c in cells
                 if isinstance(c.cell_contents, str)]
        assert "collection.persona_act" in names, name


def test_a_blocking_readiness_failure_refuses_create_and_join_with_the_run_routes_words(
        conn, api, world, monkeypatch):
    from noctornal_api.http.routers import collection as router

    monkeypatch.setattr(router, "blocking_failures", lambda _c: ["security_officer_present"])
    spec = _chat_spec()
    api.telegram(tp.fixture_for(spec, world["uid"]))
    run_words = api.client.post(f"{API}/sources/{uuid.uuid4()}/run", headers=world["hdr"],
                                json={}).json()["detail"]
    r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                        json=_body(world, f"@{spec['username']}"))
    assert r.status_code == 409 and r.json()["detail"] == run_words
    ch = _member_chat(conn, api, world)
    j = api.client.post(f"{TG}/chats/{ch['source']}/join", headers=world["hdr"],
                        json={"acknowledge_overt": True, "note": "a long enough note"})
    assert j.status_code == 409 and j.json()["detail"] == run_words
    assert api.factory.transports == []


# --- the Telegram lines in the collection routes ---------------------------------------

def test_the_run_route_reads_a_telegram_chat_and_the_documents_carry_their_capture_record(
        conn, api, world):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"])
    h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                persona_id=world["persona"], source_ids=[ch["source"]])
    api.telegram(tp.fixture_for(ch["spec"], world["uid"], tp.messages(1, 2)))
    due = api.client.get(f"{API}/sources/due", headers=world["hdr"]).json()
    entry = next(d for d in due["due"] if d["id"] == str(ch["source"]))
    assert entry["telegram"]["chat"] == ch["durable_id"]
    assert entry["telegram"]["access_mode"] == "PUBLIC_READ" and entry["telegram"]["egress"]
    run = api.client.post(f"{API}/sources/{ch['source']}/run", headers=world["hdr"], json={})
    assert run.status_code == 200 and run.json()["status"] == "OK", run.text
    docs = api.client.get(f"{API}/documents", headers=world["hdr"],
                          params={"source_id": str(ch["source"])}).json()["documents"]
    assert docs and all(d["telegram"]["chat"] == ch["durable_id"] for d in docs)
    assert {d["telegram"]["message_id"] for d in docs} == {1, 2}


def test_the_personas_route_carries_the_telegram_facts_and_no_secret(conn, api, world):
    rows = api.client.get(f"{API}/personas", headers=world["hdr"]).json()["personas"]
    mine = next(p for p in rows if p["id"] == str(world["persona"]))
    assert mine["telegram"]["platform_uid"] == world["uid"]
    assert mine["telegram"]["session_enrolled_at"]
    text = repr(mine)
    assert "0123456789abcdef" not in text and "api_hash" not in text


def test_a_telegram_target_shows_the_confirmer_which_chat_it_is(conn, api, world):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"],
                 access_mode="MEMBER")
    view = h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                       persona_id=world["persona"], source_ids=[ch["source"]],
                       scope="MEMBER_READ", member_ref="COVERT-2026-2", confirm=False)
    target = view["targets"][0]
    assert target["chat"]["durable_id"] == ch["durable_id"]
    assert target["chat"]["access_mode"] == "MEMBER"
    assert target["chat"]["username_at_resolve"] == ch["spec"]["username"]


def test_the_window_route_sets_hours_refuses_a_malformed_one_and_hides_what_it_must(
        conn, api, world):
    url = f"{TG}/personas/{world['persona']}/window"
    assert api.client.post(url, headers=world["hdr"],
                           json={"active_window_utc": "25:00-07:00"}).status_code == 422
    r = api.client.post(url, headers=world["hdr"], json={"active_window_utc": "07:00-23:00"})
    assert r.status_code == 200 and r.json()["active_window_utc"] == "07:00-23:00"
    tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"],
            classification="RED")
    _uid, amber = _caller(conn, clearance="AMBER")
    hidden = api.client.post(url, headers=amber, json={"active_window_utc": None})
    missing = api.client.post(f"{TG}/personas/{uuid.uuid4()}/window", headers=amber,
                              json={"active_window_utc": None})
    assert hidden.status_code == missing.status_code == 404
    assert hidden.json() == missing.json()


def test_the_chat_listing_says_whether_telegram_collection_is_on(conn, api, world,
                                                                monkeypatch):
    body = api.client.get(f"{TG}/chats", headers=world["hdr"]).json()
    assert body["telegram"]["available"] and body["telegram"]["ceiling"] == "AMBER"
    assert body["telegram"]["sentence"] is None
    monkeypatch.delenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING")
    off = api.client.get(f"{TG}/chats", headers=world["hdr"]).json()["telegram"]
    assert off["ceiling"] is None and "Telegram collection is off" in off["sentence"]


# --- a persona's whole path -------------------------------------------------------

def test_a_telegram_persona_is_created_through_the_collection_route_with_its_device(
        conn, api, world):
    api.telegram(tp.fixture_for(_chat_spec(), world["uid"]))
    egress = h.egress_profile(conn, P)
    body = {"handle": f"{P}ghost", "platform": "TELEGRAM",
            "egress_profile_id": str(egress), "fingerprint": dict(tf.DEVICE)}
    _u, stale = _caller(conn, fresh=False)
    assert api.client.post(f"{API}/personas", headers=stale, json=body).status_code == 403
    missing = api.client.post(f"{API}/personas", headers=world["hdr"],
                              json={**body, "fingerprint": {"device_model": "Pixel 7"}})
    assert missing.status_code == 400
    assert "records its system version" in missing.json()["detail"]
    made = api.client.post(f"{API}/personas", headers=world["hdr"], json=body)
    assert made.status_code == 201, made.text
    taken = api.client.post(f"{API}/personas", headers=world["hdr"],
                            json={**body, "handle": f"{P}second"})
    assert taken.status_code == 400
    assert "one persona, one egress profile" in taken.json()["detail"]


def test_a_new_persona_reaches_its_first_chat(conn, api, world):
    """An authority with no source allows the
    persona's acts; the chat looked up under it becomes a target a second
    person confirms, and only then is it read."""
    spec = _chat_spec()
    api.telegram(tp.fixture_for(spec, world["uid"], tp.messages(1, 3)))
    made = api.client.post(f"{TG}/chats", headers=world["hdr"],
                           json=_body(world, f"@{spec['username']}"))
    assert made.status_code == 201, made.text
    source = made.json()["source"]["id"]
    blocked = api.client.post(f"{API}/sources/{source}/run", headers=world["hdr"], json={})
    assert blocked.json()["status"] == "BLOCKED", "no target yet: no read"
    added = api.client.post(f"{API}/authorities/{world['authority']}/targets",
                            headers=world["hdr"], json={"source_ids": [source]})
    assert added.status_code == 200, added.text
    target = next(t for t in added.json()["authority"]["targets"]
                  if t["source_id"] == source)
    assert target["chat"]["durable_id"] == f"c:{spec['peer_id']}"
    confirmed = api.client.post(f"{API}/authorities/{world['authority']}/confirm",
                                headers=world["officer"],
                                json={"note": "checked the chat id against the order",
                                      "target_ids": [target["id"]]})
    assert confirmed.status_code == 200, confirmed.text
    run = api.client.post(f"{API}/sources/{source}/run", headers=world["hdr"], json={})
    assert run.status_code == 200 and run.json()["status"] == "OK", run.text
    assert run.json()["items_new"] == 3


def test_marking_a_member_chat_needs_a_fresh_second_factor(conn, api, world):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"])
    api.telegram(tp.fixture_for(ch["spec"], world["uid"]))
    _u, stale = _caller(conn, fresh=False)
    r = api.client.post(f"{TG}/chats/{ch['source']}/member", headers=stale,
                        json={"reason": "it is a member chat now"})
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
    assert conn.execute("SELECT access_mode FROM collect.telegram_chat WHERE source_id = %s",
                        (ch["source"],)).fetchone()[0] == "PUBLIC_READ"
