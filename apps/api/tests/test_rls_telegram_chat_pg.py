"""Row-level security on which Telegram chat a source is (F51, 2026-10-02).

0129 puts `collect.telegram_chat` under a policy that carries its source's
label inline (CUSTOM_SOURCE_CHILD): the source itself is exempt, because
the egress proxy reads it. Each test runs the policy, a service or a route
as the request role, bound by a real session's proof, or as the system
role, with the fixtures seeded as the owner (rls_support); the routes run
in production's shape (NOCTORNAL_TEST_ASSUME_ROLE):

- a chat is held to its source's label at the case-less ceiling: a grant
  scoped to a case never raises it, a global one does; an unbound
  connection sees and writes nothing; the request role writes no chat
  under a source above its user;
- the duplicate-key side channel stays closed: a chat already added under
  a source above the adder answers exactly as an unresolvable reference,
  and so does one added between the check and the insert;
- what each caller could do before still works: adding a chat, naming a
  visible duplicate, the chat listing, the due list's chat line, a manual
  run, the confirmer's view of a target's chat, and each attended act;
- an act whose chat went above its caller during the act is refused as
  for a missing chat and records nothing, half a change included;
- the poll's reads and writes of a chat above every user (refusal, plan,
  the deletion mark, what a session learnt, a migration, a lost
  membership) run as the system role;
- the policy is initplans only, never a per-row definer call.

Gated like the other row-security tests. Account, persona and source
prefix `rlstg-`.
"""
from __future__ import annotations

import hashlib
import uuid
from types import SimpleNamespace

import psycopg
import pytest

import collection_helpers as h
import rls_support as s
import telegram_fake as tf
import telegram_pg as tp

pytestmark = s.GATED

P = "rlstg-"
API = "/api/v1/collection"
TG = f"{API}/telegram"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    tp.teardown(c, P)
    s.cleanup(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def api(owner, monkeypatch):
    from noctornal_api.http.routers import collection as router

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    monkeypatch.setattr(router, "blocking_failures", lambda _c: [])
    tf.guard_sockets(monkeypatch)
    tf.patch_routes(monkeypatch)
    client, app = h.client()
    return SimpleNamespace(client=client, app=app)


def _use(api, factory) -> None:
    """The routes' Telegram transport and the poll's adapter, both fakes."""
    from noctornal_api.collection import RssAdapter
    from noctornal_api.http.routers import collection as router
    from noctornal_api.http.routers import collection_telegram as tgr
    from noctornal_api.telegram import TelegramAdapter

    registry = {"rss": RssAdapter(),
                "telegram": TelegramAdapter(factory, sleep=tf._no_sleep)}
    api.app.dependency_overrides[tgr.get_transport_factory] = lambda: factory
    api.app.dependency_overrides[router.get_adapters] = lambda: registry


def _caller(owner, clearance: str = "AMBER", roles=("COLLECTOR",)) -> tuple:
    uid, email = h.user(owner, P, clearance=clearance, roles=roles)
    return uid, h.auth(h.session(owner, email))


def _world(owner) -> dict:
    recorder = h.user(owner, P, roles=("COLLECTOR",))[0]
    confirmer = h.user(owner, P, roles=("SECURITY_OFFICER",))[0]
    pid, _egress, uid = tp.persona(owner, P)
    # The persona's own authority with no source: its acts, and no read.
    h.authority(owner, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[])
    caller, hdr = _caller(owner)
    return {"recorder": recorder, "confirmer": confirmer, "persona": pid,
            "uid": uid, "caller": caller, "hdr": hdr}


def _spec(**over) -> dict:
    spec = {"peer_type": "CHANNEL", "peer_id": tp.rand_id(), "access_hash": 991,
            "username": f"tg{uuid.uuid4().hex[:10]}", "title": "Example chat",
            "is_member": False}
    spec.update(over)
    return spec


def _body(w: dict, spec: dict, **over) -> dict:
    body = {"persona_id": str(w["persona"]), "ref": f"@{spec['username']}",
            "name": f"{P}chat", "classification": "AMBER",
            "access_mode": "PUBLIC_READ"}
    body.update(over)
    return body


def _as_owner(sql: str, params=()) -> None:
    """A committed change from outside the request, as another manager's
    reclassification would be."""
    c = s.owner_conn()
    try:
        c.execute(sql, params)
    finally:
        c.close()


def _rested(owner, *personas) -> None:
    """Skip the persona's twenty-second gap between two acts."""
    owner.execute("UPDATE collect.collection_account SET last_request_at = NULL "
                  "WHERE id = ANY(%s)", (list(personas),))


def _audits(owner, action: str, object_id) -> int:
    return s.count(owner, "SELECT count(*) FROM audit.event WHERE action = %s "
                          "AND object_id = %s", (action, object_id))


def _worker():
    from noctornal_api.db import connect
    c = connect()
    c.execute(f"SET ROLE {s.WORKER_ROLE}")
    return c


def _ids(conn, sql: str, params=None) -> set:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


def _member_chat(owner, w: dict, *, peer_type: str = "MEGAGROUP",
                 member_since: bool = False) -> dict:
    """A member chat read by the world's persona, its member target confirmed."""
    ch = tp.chat(owner, P, persona_id=w["persona"], resolved_by=w["recorder"],
                 access_mode="MEMBER", peer_type=peer_type, member_since=member_since,
                 username="auto" if peer_type != "CHAT" else None,
                 access_hash=None if peer_type == "CHAT" else 55)
    h.authority(owner, recorder=w["recorder"], confirmer=w["confirmer"],
                persona_id=w["persona"], source_ids=[ch["source"]],
                scope="MEMBER_READ", member_ref="COVERT-2026-51")
    return ch


class _RaisedMidAct(tf.FakeTransport):
    """A fake whose `on` call raises the chat's source above every caller
    first: another manager's reclassification landing during the act."""

    def __init__(self, fx, *, on: str, source, **kw):
        super().__init__(fx, **kw)
        self._on, self._source = on, source

    def _call(self, _method, **kw):
        super()._call(_method, **kw)
        if _method == self._on:
            _as_owner("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                      (self._source,))


def _raising(fx, *, on: str, source, **kw):
    def make(secret, route, fingerprint, *, proxy):
        return _RaisedMidAct(fx, on=on, source=source, secret=secret, proxy=proxy, **kw)
    return make


# ---------------------------------------------------------------------------
# The policy
# ---------------------------------------------------------------------------

def test_a_chat_is_held_to_its_source_label_at_the_case_less_ceiling(owner):
    analyst = s.user(owner, "AMBER", prefix=P)
    boss = s.user(owner, "RED", prefix=P)
    red_case = s.case(owner, boss, "RED")
    s.assign(owner, red_case, analyst)
    pid, _e, _uid = tp.persona(owner, P)
    amber = tp.chat(owner, P, persona_id=pid, resolved_by=boss)
    red = tp.chat(owner, P, persona_id=pid, resolved_by=boss, classification="RED")
    ids = [amber["source"], red["source"]]
    mine = "SELECT source_id FROM collect.telegram_chat WHERE source_id = ANY(%s)"
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        assert _ids(app, mine, (ids,)) == {amber["source"]}
        assert app.execute("UPDATE collect.telegram_chat SET is_forum = true "
                           "WHERE source_id = %s", (red["source"],)).rowcount == 0
        assert app.execute("UPDATE collect.telegram_chat SET is_forum = true "
                           "WHERE source_id = %s", (amber["source"],)).rowcount == 1
        above = h.source(owner, P, kind="TELEGRAM", parser="telegram",
                         classification="RED", base_url=None, persona=pid)
        peer = tp.rand_id()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO collect.telegram_chat
                       (source_id, peer_type, peer_id, durable_id, access_mode,
                        provenance_class, resolved_by)
                   VALUES (%s, 'CHANNEL', %s, %s, 'PUBLIC_READ', 'OPEN_GROUP', %s)""",
                (above, peer, f"c:{peer}", analyst))
        # The database's own side channel, which is why the route's
        # duplicate check must never leave it to the INSERT: the unique
        # durable id is not row security's, and it names a hidden chat.
        visible = h.source(owner, P, kind="TELEGRAM", parser="telegram",
                           base_url=None, persona=pid)
        with pytest.raises(psycopg.errors.UniqueViolation):
            app.execute(
                """INSERT INTO collect.telegram_chat
                       (source_id, peer_type, peer_id, durable_id, access_mode,
                        provenance_class, resolved_by)
                   VALUES (%s, 'CHANNEL', %s, %s, 'PUBLIC_READ', 'OPEN_GROUP', %s)""",
                (visible, int(red["durable_id"][2:]), red["durable_id"], analyst))
        # A grant scoped to a case never raises a row that belongs to no
        # case; a global one does.
        s.break_glass(owner, analyst, "RED", red_case)
        assert _ids(app, mine, (ids,)) == {amber["source"]}
        s.break_glass(owner, analyst, "RED")
        assert _ids(app, mine, (ids,)) == set(ids)
    finally:
        app.close()
    unbound = s.app_conn()
    try:
        assert _ids(unbound, mine, (ids,)) == set()
        assert unbound.execute("UPDATE collect.telegram_chat SET is_forum = true "
                               "WHERE source_id = %s", (amber["source"],)).rowcount == 0
    finally:
        unbound.close()
    worker = _worker()
    try:
        assert _ids(worker, mine, (ids,)) == set(ids)
        assert worker.execute("UPDATE collect.telegram_chat SET noforwards = true "
                              "WHERE source_id = %s", (red["source"],)).rowcount == 1
    finally:
        worker.close()


def test_the_policy_is_initplans_never_a_per_row_call(owner):
    analyst = s.user(owner, "AMBER", prefix=P)
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        for sql, params in (
                ("SELECT source_id FROM collect.telegram_chat WHERE durable_id = %s",
                 ("c:1",)),
                ("SELECT c.source_id FROM collect.telegram_chat c "
                 "JOIN collect.source s ON s.id = c.source_id WHERE s.is_active", None)):
            assert s.per_row_definer_calls(app, sql, params) == [], sql
    finally:
        app.close()


# ---------------------------------------------------------------------------
# Adding a chat: the duplicate-key side channel
# ---------------------------------------------------------------------------

def test_a_chat_already_added_above_the_adder_answers_like_an_unresolvable_one(owner, api):
    w = _world(owner)
    spec = _spec()
    _use(api, tf.FakeFactory(tp.fixture_for(spec, w["uid"])))
    made = api.client.post(f"{TG}/chats", headers=w["hdr"], json=_body(w, spec))
    assert made.status_code == 201, made.text
    assert made.json()["chat"]["durable_id"] == f"c:{spec['peer_id']}"
    _rested(owner, w["persona"])
    again = api.client.post(f"{TG}/chats", headers=w["hdr"],
                            json=_body(w, spec, name=f"{P}again"))
    assert again.status_code == 409 and f"{P}chat" in again.json()["detail"], again.text
    owner.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                  (made.json()["source"]["id"],))

    other_pid, _e, other_uid = tp.persona(owner, P)
    h.authority(owner, recorder=w["recorder"], confirmer=w["confirmer"],
                persona_id=other_pid, source_ids=[])
    adder, hdr = _caller(owner)
    other = dict(w, persona=other_pid, uid=other_uid, hdr=hdr)
    _use(api, tf.FakeFactory(tp.fixture_for(spec, other_uid)))
    hidden = api.client.post(f"{TG}/chats", headers=hdr,
                             json=_body(other, spec, name=f"{P}hidden"))
    _rested(owner, other_pid)
    _use(api, tf.FakeFactory(tp.fixture_for(_spec(), other_uid)))
    missing = api.client.post(f"{TG}/chats", headers=hdr,
                              json=_body(other, spec, ref="@nobodyhasthisname",
                                         name=f"{P}missing"))
    assert hidden.status_code == missing.status_code == 422, (hidden.text, missing.text)
    assert hidden.json() == missing.json()
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE action = "
                          "'TELEGRAM_CHAT_DUPLICATE_HIDDEN' AND actor_id = %s",
                   (adder,)) == 1
    assert s.count(owner, "SELECT count(*) FROM collect.source WHERE name = %s",
                   (f"{P}hidden",)) == 0


def test_a_chat_added_between_the_check_and_the_insert_answers_the_same(
        owner, api, monkeypatch):
    """The check sees nothing, another manager's chat lands, and the INSERT
    meets the unique durable id: answered by the same check, never as a
    duplicate-key error (a 500 until 2026-10-02)."""
    from noctornal_api import telegram_service

    w = _world(owner)
    spec = _spec()
    elsewhere, _e, _u = tp.persona(owner, P)
    tp.chat(owner, P, persona_id=elsewhere, resolved_by=w["recorder"],
            classification="RED", peer_id=spec["peer_id"], username=spec["username"])
    real = telegram_service._existing_chat
    calls: list = []

    def late(conn, durable_id, clearance, compartments=None):
        calls.append(durable_id)
        return (None if len(calls) == 1
                else real(conn, durable_id, clearance, compartments))

    monkeypatch.setattr(telegram_service, "_existing_chat", late)
    _use(api, tf.FakeFactory(tp.fixture_for(spec, w["uid"])))
    raced = api.client.post(f"{TG}/chats", headers=w["hdr"],
                            json=_body(w, spec, name=f"{P}raced"))
    monkeypatch.setattr(telegram_service, "_existing_chat", real)
    _rested(owner, w["persona"])
    _use(api, tf.FakeFactory(tp.fixture_for(_spec(), w["uid"])))
    missing = api.client.post(f"{TG}/chats", headers=w["hdr"],
                              json=_body(w, spec, ref="@nobodyhasthisname",
                                         name=f"{P}missing"))
    assert len(calls) == 2, "the insert's refusal asked the check again"
    assert raced.status_code == missing.status_code == 422, (raced.text, missing.text)
    assert raced.json() == missing.json()
    assert s.count(owner, "SELECT count(*) FROM collect.source WHERE name = %s",
                   (f"{P}raced",)) == 0, "the source went back with its chat"
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE action = "
                          "'TELEGRAM_CHAT_DUPLICATE_HIDDEN' AND actor_id = %s",
                   (w["caller"],)) == 1


# ---------------------------------------------------------------------------
# The readers that stay on the request connection
# ---------------------------------------------------------------------------

def test_the_listing_the_due_line_a_run_and_the_confirmers_view_read_as_before(owner, api):
    w = _world(owner)
    ch = tp.chat(owner, P, persona_id=w["persona"], resolved_by=w["recorder"])
    h.authority(owner, recorder=w["recorder"], confirmer=w["confirmer"],
                persona_id=w["persona"], source_ids=[ch["source"]])
    _use(api, tf.FakeFactory(tp.fixture_for(ch["spec"], w["uid"], tp.messages(1, 2))))

    listed = api.client.get(f"{TG}/chats", headers=w["hdr"])
    assert listed.status_code == 200, listed.text
    assert str(ch["source"]) in {c["source_id"] for c in listed.json()["chats"]}
    due = api.client.get(f"{API}/sources/due", headers=w["hdr"]).json()
    entry = next(d for d in due["due"] if d["id"] == str(ch["source"]))
    assert entry["telegram"]["chat"] == ch["durable_id"]
    run = api.client.post(f"{API}/sources/{ch['source']}/run", headers=w["hdr"], json={})
    assert run.status_code == 200 and run.json()["status"] == "OK", run.text

    # The confirmer reads each target's chat on the request connection. A
    # target's source raised above the officer raises its authority with it
    # (`collect.raise_authority_labels`), so the officer then sees neither,
    # and never a chat under a source above them.
    pid, _e, _u = tp.persona(owner, P)
    raised = tp.chat(owner, P, persona_id=pid, resolved_by=w["recorder"])
    kept = tp.chat(owner, P, persona_id=pid, resolved_by=w["recorder"])
    view = h.authority(owner, recorder=w["recorder"], confirmer=w["confirmer"],
                       persona_id=pid, source_ids=[raised["source"], kept["source"]],
                       confirm=False)
    both = {raised["durable_id"], kept["durable_id"]}
    _uid, amber = _caller(owner, "AMBER", roles=("SECURITY_OFFICER",))
    _uid, red = _caller(owner, "RED", roles=("SECURITY_OFFICER",))

    def review(hdr) -> dict | None:
        r = api.client.get(f"{API}/authorities/review", headers=hdr)
        assert r.status_code == 200, r.text
        return next((a for a in r.json()["pending"] if a["id"] == view["id"]), None)

    before = review(amber)
    assert {t["chat"]["durable_id"] for t in before["targets"]} == both
    owner.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                  (raised["source"],))
    assert review(amber) is None
    after = review(red)
    assert after["has_hidden_targets"] is False
    assert {t["chat"]["durable_id"] for t in after["targets"]} == both


# ---------------------------------------------------------------------------
# The attended acts
# ---------------------------------------------------------------------------

def _missing_answer(api, hdr, path: str, body) -> dict:
    r = api.client.post(f"{TG}/chats/{uuid.uuid4()}/{path}", headers=hdr, json=body)
    assert r.status_code == 404, r.text
    return r.json()


def test_a_join_records_as_before_and_one_whose_chat_went_above_its_caller_records_nothing(
        owner, api):
    w = _world(owner)
    note = {"acknowledge_overt": True, "note": "joining for the operation"}
    ch = _member_chat(owner, w)
    _use(api, tf.FakeFactory(tp.fixture_for(ch["spec"], w["uid"]), allow_join=True))
    r = api.client.post(f"{TG}/chats/{ch['source']}/join", headers=w["hdr"], json=note)
    assert r.status_code == 200, r.text
    assert owner.execute("SELECT joined_by FROM collect.telegram_chat WHERE source_id = %s",
                         (ch["source"],)).fetchone()[0] == w["caller"]

    _rested(owner, w["persona"])
    raised = _member_chat(owner, w)
    _use(api, _raising(tp.fixture_for(raised["spec"], w["uid"]), on="join",
                       source=raised["source"], allow_join=True))
    r = api.client.post(f"{TG}/chats/{raised['source']}/join", headers=w["hdr"], json=note)
    assert r.status_code == 404, r.text
    assert r.json() == _missing_answer(api, w["hdr"], "join", note)
    row = owner.execute("SELECT joined_by, member_since_observed FROM collect.telegram_chat "
                        "WHERE source_id = %s", (raised["source"],)).fetchone()
    assert row == (None, None)
    assert _audits(owner, "TELEGRAM_CHAT_JOINED", raised["source"]) == 0


def test_a_membership_check_records_as_before_and_one_raised_mid_act_records_nothing(
        owner, api):
    w = _world(owner)
    ch = _member_chat(owner, w, peer_type="CHAT")
    _use(api, tf.FakeFactory(tp.fixture_for(dict(ch["spec"], is_member=True), w["uid"])))
    r = api.client.post(f"{TG}/chats/{ch['source']}/membership", headers=w["hdr"])
    assert r.status_code == 200 and r.json()["member"] is True, r.text

    _rested(owner, w["persona"])
    raised = _member_chat(owner, w, peer_type="CHAT")
    _use(api, _raising(tp.fixture_for(dict(raised["spec"], is_member=True), w["uid"]),
                       on="lookup", source=raised["source"]))
    r = api.client.post(f"{TG}/chats/{raised['source']}/membership", headers=w["hdr"])
    assert r.status_code == 404, r.text
    assert r.json() == _missing_answer(api, w["hdr"], "membership", None)
    assert owner.execute("SELECT member_since_observed FROM collect.telegram_chat "
                         "WHERE source_id = %s", (raised["source"],)).fetchone()[0] is None
    assert _audits(owner, "TELEGRAM_CHAT_MEMBERSHIP_SEEN", raised["source"]) == 0


def test_a_mark_changes_chat_and_source_together_or_neither(owner, api, monkeypatch):
    from noctornal_api import telegram_service

    w = _world(owner)
    body = {"reason": "the persona joined on its phone"}
    ch = tp.chat(owner, P, persona_id=w["persona"], resolved_by=w["recorder"])
    h.authority(owner, recorder=w["recorder"], confirmer=w["confirmer"],
                persona_id=w["persona"], source_ids=[ch["source"]],
                scope="MEMBER_READ", member_ref="COVERT-2026-52")
    _use(api, tf.FakeFactory(tp.fixture_for(dict(ch["spec"], is_member=True), w["uid"])))
    r = api.client.post(f"{TG}/chats/{ch['source']}/member", headers=w["hdr"], json=body)
    assert r.status_code == 200 and r.json()["marked"], r.text

    _rested(owner, w["persona"])
    raised = tp.chat(owner, P, persona_id=w["persona"], resolved_by=w["recorder"])
    real = telegram_service._chat_row

    def read_then_raised(conn, source_id, clearance, compartments=None):
        chat = real(conn, source_id, clearance, compartments)
        _as_owner("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                  (source_id,))
        return chat

    monkeypatch.setattr(telegram_service, "_chat_row", read_then_raised)
    r = api.client.post(f"{TG}/chats/{raised['source']}/member", headers=w["hdr"],
                        json=body)
    monkeypatch.setattr(telegram_service, "_chat_row", real)
    assert r.status_code == 404, r.text
    assert r.json() == _missing_answer(api, w["hdr"], "member", body)
    row = owner.execute(
        """SELECT c.access_mode, s.parser_config FROM collect.telegram_chat c
             JOIN collect.source s ON s.id = c.source_id WHERE c.source_id = %s""",
        (raised["source"],)).fetchone()
    assert row == ("PUBLIC_READ", {"access_mode": "PUBLIC_READ"}), (
        "a source read as a member chat beside a public chat record is never polled")
    assert _audits(owner, "SOURCE_ACCESS_MODE_CHANGED", raised["source"]) == 0


def test_a_rebind_moves_source_and_chat_together_or_neither(owner, api, monkeypatch):
    from noctornal_api.collection import CollectionService

    w = _world(owner)
    new_pid, _e, new_uid = tp.persona(owner, P)
    h.authority(owner, recorder=w["recorder"], confirmer=w["confirmer"],
                persona_id=new_pid, source_ids=[], scope="MEMBER_READ",
                member_ref="COVERT-2026-53")
    body = {"persona_id": str(new_pid), "reason": "the old one burnt"}
    ch = _member_chat(owner, w, peer_type="CHAT", member_since=True)
    _use(api, tf.FakeFactory(tp.fixture_for(dict(ch["spec"], is_member=True), new_uid)))
    r = api.client.post(f"{TG}/chats/{ch['source']}/persona", headers=w["hdr"], json=body)
    assert r.status_code == 200, r.text
    assert owner.execute("SELECT collection_account_id FROM collect.source WHERE id = %s",
                         (ch["source"],)).fetchone()[0] == new_pid

    _rested(owner, w["persona"], new_pid)
    raised = _member_chat(owner, w, peer_type="CHAT", member_since=True)
    real = CollectionService.bind_source

    def bound_then_lowered(self, *args, **kwargs):
        # The caller's clearance falls after the bind: the chat's write is
        # the first statement the policy then refuses to show a row to.
        out = real(self, *args, **kwargs)
        _as_owner("UPDATE iam.app_user SET tlp_clearance = 'GREEN' WHERE id = %s",
                  (w["caller"],))
        return out

    monkeypatch.setattr(CollectionService, "bind_source", bound_then_lowered)
    _use(api, tf.FakeFactory(tp.fixture_for(dict(raised["spec"], is_member=True), new_uid)))
    r = api.client.post(f"{TG}/chats/{raised['source']}/persona", headers=w["hdr"],
                        json=body)
    monkeypatch.setattr(CollectionService, "bind_source", real)
    assert r.status_code == 404, r.text
    assert r.json() == _missing_answer(api, w["hdr"], "persona", body)
    row = owner.execute(
        """SELECT s.collection_account_id, c.member_since_observed IS NOT NULL
             FROM collect.source s JOIN collect.telegram_chat c ON c.source_id = s.id
            WHERE s.id = %s""", (raised["source"],)).fetchone()
    assert row == (w["persona"], True), "the bind went back with the chat's write"
    assert _audits(owner, "SOURCE_PERSONA_CHANGED", raised["source"]) == 0


# ---------------------------------------------------------------------------
# The poll, as the system role
# ---------------------------------------------------------------------------

def test_the_poll_reads_and_writes_a_chat_above_every_user_as_the_system_role(
        owner, monkeypatch):
    from noctornal_api.collection import _source_row
    from noctornal_api.telegram import TelegramAdapter

    tf.patch_routes(monkeypatch)
    boss = s.user(owner, "RED", prefix=P)
    analyst = s.user(owner, "AMBER", prefix=P)
    pid, _e, uid = tp.persona(owner, P)
    ch = tp.chat(owner, P, persona_id=pid, resolved_by=boss, classification="RED",
                 access_mode="MEMBER", member_since=True)
    external = f"{ch['durable_id']}/5"
    text = f"rlstg message {uuid.uuid4().hex}"
    doc = owner.execute(
        """INSERT INTO collect.document (source_id, external_id, title, body_text,
                                         content_sha256, classification)
           VALUES (%s, %s, %s, %s, %s, 'RED') RETURNING id""",
        (ch["source"], external, f"{P}message", text,
         hashlib.sha256(text.encode()).digest())).fetchone()[0]
    owner.execute(
        """INSERT INTO collect.telegram_message
               (document_id, source_id, chat_durable_id, message_id, seen_via_uid)
           VALUES (%s, %s, %s, 5, %s)""", (doc, ch["source"], ch["durable_id"], uid))

    # The request role's view of the same chat: nothing, so nothing to mark.
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        assert app.execute("SELECT 1 FROM collect.telegram_chat WHERE source_id = %s",
                           (ch["source"],)).fetchone() is None
    finally:
        app.close()

    adapter = TelegramAdapter()
    worker = _worker()
    try:
        source = _source_row(worker, ch["source"], None)
        refusal = adapter.refusal(worker, source)
        assert refusal is None or "no chat record" not in refusal, refusal
        plan = adapter.plan(worker, source, {"id": pid, "platform_uid": uid})
        assert plan.chat.durable_id == ch["durable_id"]
        run_id = uuid.uuid4()
        with worker.transaction():
            adapter.commit(worker, source_id=ch["source"], run_id=run_id,
                           persona_id=pid, stored=[], existing=[],
                           fetched=SimpleNamespace(
                               deleted_external_ids=[external],
                               chat_update={"access_hash": 4242, "is_forum": True,
                                            "noforwards": True, "is_member": True}))
        adapter._remember(ch["source"], membership_lost=True,
                          migrated_to=f"c:{tp.rand_id()}")
        with worker.transaction():
            adapter.settle(worker, source_id=ch["source"], persona_id=pid,
                           run_id=run_id, status="OK", error=None)
    finally:
        worker.close()
    assert owner.execute("SELECT deleted_seen_at IS NOT NULL FROM collect.telegram_message "
                         "WHERE document_id = %s", (doc,)).fetchone()[0] is True
    row = owner.execute(
        """SELECT access_hash, access_hash_account_id, is_forum, noforwards,
                  member_since_observed, migrated_to IS NOT NULL
             FROM collect.telegram_chat WHERE source_id = %s""",
        (ch["source"],)).fetchone()
    assert row == (4242, pid, True, True, None, True)
    assert _audits(owner, "TELEGRAM_CHAT_MIGRATED", ch["source"]) == 1


# ---------------------------------------------------------------------------
# The source's compartments (docs/17 F43, 0164, 2026-10-02)
# ---------------------------------------------------------------------------

def test_a_chat_under_a_compartmented_source_is_hidden_from_a_reader_who_lacks_the_key(owner):
    """0164 restates 0129's policy with the source's compartments held: a
    chat under a compartmented source is seen and written only by a bound
    user who holds the key, whatever their clearance; the worker and the
    owner still see it; the policy stays initplans."""
    key = f"RLSTG{uuid.uuid4().hex[:6].upper()}"
    holder = s.user(owner, "RED", (key,), prefix=P)
    lacking = s.user(owner, "RED", prefix=P)
    pid, _e, _uid = tp.persona(owner, P)
    plain = tp.chat(owner, P, persona_id=pid, resolved_by=holder)
    locked = tp.chat(owner, P, persona_id=pid, resolved_by=holder)
    owner.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                  "ON CONFLICT (key) DO NOTHING", (key, "Telegram chat test"))
    owner.execute("UPDATE collect.source SET compartments = %s WHERE id = %s",
                  ([key], locked["source"]))
    ids = [plain["source"], locked["source"]]
    mine = "SELECT source_id FROM collect.telegram_chat WHERE source_id = ANY(%s)"
    try:
        _chat_compartment_checks(owner, key, plain, locked, ids, mine, holder, lacking)
    finally:
        # The source outlives the test (an authority may name it); its key
        # must not, or 0163's downgrade refuses the suite's round trip.
        owner.execute("UPDATE collect.source SET compartments = '{}' WHERE id = %s",
                      (locked["source"],))


def _chat_compartment_checks(owner, key, plain, locked, ids, mine, holder, lacking):
    _, raw = s.session(owner, lacking)
    app = s.app_conn(raw)
    try:
        assert _ids(app, mine, (ids,)) == {plain["source"]}
        assert app.execute("UPDATE collect.telegram_chat SET is_forum = true "
                           "WHERE source_id = %s", (locked["source"],)).rowcount == 0
        assert s.per_row_definer_calls(app, mine, (ids,)) == []
        # A global break-glass raises the ceiling and never the compartments.
        s.break_glass(owner, lacking, "RED")
        assert _ids(app, mine, (ids,)) == {plain["source"]}
    finally:
        app.close()
    _, raw = s.session(owner, holder)
    app = s.app_conn(raw)
    try:
        assert _ids(app, mine, (ids,)) == set(ids)
        assert app.execute("UPDATE collect.telegram_chat SET is_forum = true "
                           "WHERE source_id = %s", (locked["source"],)).rowcount == 1
    finally:
        app.close()
    worker = _worker()
    try:
        assert _ids(worker, mine, (ids,)) == set(ids)
    finally:
        worker.close()
    # The listing route reads the same rule (collection._SOURCE_VISIBLE_HELD).
    from noctornal_api.telegram_service import TelegramChats
    chats = TelegramChats(owner)
    seen = {c["source_id"] for c in chats.listing(clearance="RED",
                                                  compartments=frozenset())["chats"]}
    assert str(locked["source"]) not in seen and str(plain["source"]) in seen
    seen = {c["source_id"] for c in chats.listing(clearance="RED",
                                                  compartments=frozenset({key}))["chats"]}
    assert str(locked["source"]) in seen
