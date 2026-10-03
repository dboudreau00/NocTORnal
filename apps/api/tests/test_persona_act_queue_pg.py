"""The persona act queue and the collector, against the database (ROADMAP-
REMAINING "A collector process", 2026-10-02). DATABASE_URL-gated.

The suite runs persona acts inline (conftest), as development does; every
test here turns the inline mode OFF, so a route queues its act and answers
202, and `persona_acts.drain` (what scripts/collector.py runs) does the
work, with a fake Telegram and no network. What is held: the act carries no
secret and runs nothing until the collector does; the collector asks again,
as the person who asked, and runs the route's own code; a refusal is the
route's own sentence; an act expires rather than runs late, and one a dead
collector left is never repeated; the row is a record; another person, or
the same one below the act's label now, cannot see it; the vault opens
nothing without the persona key and refuses a credential sealed before the
split by name, which the move then fixes.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

import collection_helpers as h
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")

P = "test-pact-"
API = "/api/v1/collection"
TG = f"{API}/telegram"
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    from noctornal_api.http.routers import collection as router

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    # The queue, not the inline mode, and no wait: a route answers 202.
    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", "0")
    monkeypatch.setenv("NOCTORNAL_ACT_WAIT_SECONDS", "0")
    monkeypatch.setattr(router, "blocking_failures", lambda _c: [])
    tf.guard_sockets(monkeypatch)
    c = connect()
    yield c
    # Nothing a test left PENDING may outlive it: a later readiness row
    # would count it as a queue no collector drains.
    c.execute("""UPDATE collect.persona_act SET status = 'CANCELLED',
                        finished_at = clock_timestamp()
                  WHERE status = 'PENDING' AND requested_by IN (
                        SELECT id FROM iam.app_user WHERE email LIKE %s)""",
              (f"{P}%",))
    c.execute("""UPDATE collect.persona_act SET status = 'FAILED',
                        finished_at = clock_timestamp()
                  WHERE status = 'RUNNING' AND requested_by IN (
                        SELECT id FROM iam.app_user WHERE email LIKE %s)""",
              (f"{P}%",))
    # A heartbeat a test wrote is not the next test's collector.
    c.execute("DELETE FROM collect.collector_heartbeat WHERE instance LIKE %s "
              "OR instance LIKE 'collector:%%'", (f"{P}%",))
    tp.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def routes(monkeypatch):
    return tf.patch_routes(monkeypatch)


class Api:
    def __init__(self, client, app):
        self.client = client
        self.app = app
        self.factory = None
        self.registry = None

    def telegram(self, fx, **kw):
        from noctornal_api.collection import RssAdapter
        from noctornal_api.http.routers import collection as router
        from noctornal_api.http.routers import collection_telegram as tgr
        from noctornal_api.telegram import TelegramAdapter

        self.factory = tf.FakeFactory(fx, **kw)
        self.registry = {"rss": RssAdapter(),
                         "telegram": TelegramAdapter(self.factory, sleep=tf._no_sleep)}
        self.app.dependency_overrides[tgr.get_transport_factory] = lambda: self.factory
        self.app.dependency_overrides[router.get_adapters] = lambda: self.registry
        return self.factory


@pytest.fixture
def api(conn, routes):
    client, app = h.client()
    return Api(client, app)


@pytest.fixture
def world(conn, routes):
    recorder = h.user(conn, P, roles=("COLLECTOR",))[0]
    confirmer = h.user(conn, P, roles=("SECURITY_OFFICER",))[0]
    pid, egress, uid = tp.persona(conn, P)
    h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[])
    caller, email = h.user(conn, P, clearance="RED", roles=("COLLECTOR",))
    token = h.session(conn, email, fresh=True)
    yield {"recorder": recorder, "confirmer": confirmer, "persona": pid,
           "egress": egress, "uid": uid, "caller": caller, "email": email,
           "token": token, "hdr": h.auth(token)}
    # A persona is never deleted, so what a test sealed it with outlives the
    # test: a credential left malformed, or under the TOTP ring, would be
    # counted by the collector's ring verdict and the register of every
    # later run. Destroyed as PersonaVault.destroy_secret does (the
    # enrolment marker goes with it: an enrolled persona must hold one).
    conn.execute(
        """UPDATE collect.collection_account
              SET secret_ciphertext = ''::bytea, secret_key_id = NULL,
                  session_enrolled_at = NULL
            WHERE id = %s""", (pid,))


def _member_chat(conn, world, *, peer_type="CHAT", username=None, access_hash=None):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"],
                 access_mode="MEMBER", peer_type=peer_type, username=username,
                 access_hash=access_hash)
    h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                persona_id=world["persona"], source_ids=[ch["source"]],
                scope="MEMBER_READ", member_ref="COVERT-2026-41")
    return ch


def _queue_membership(conn, api, world, *, member=True):
    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=member), world["uid"]))
    r = api.client.post(f"{TG}/chats/{ch['source']}/membership", headers=world["hdr"])
    return ch, r


def _drain(conn, api, **kw):
    from noctornal_api import persona_acts

    return persona_acts.drain(conn, instance="collector:test", adapters=api.registry,
                              transport_factory=api.factory, sleep=lambda _s: None, **kw)


def _act(conn, act_id):
    row = conn.execute("""SELECT status, result, params, kind, attempts
                            FROM collect.persona_act WHERE id = %s""",
                       (act_id,)).fetchone()
    return {"status": row[0], "result": row[1], "params": row[2], "kind": row[3],
            "attempts": row[4]}


# --- the queue ------------------------------------------------------------------

def test_an_act_is_queued_with_no_secret_and_nothing_runs_until_the_collector(
        conn, api, world):
    _ch, r = _queue_membership(conn, api, world)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["queued"] is True and body["act"]["status"] == "PENDING"
    assert body["act"]["kind"] == "TELEGRAM_MEMBERSHIP"
    assert "Persona acts" in body["notice"]
    assert api.factory.methods() == [], "nothing reached Telegram from the API"
    row = conn.execute(
        """SELECT params::text, result, requested_by, session_id IS NOT NULL,
                  classification::text
             FROM collect.persona_act WHERE id = %s""",
        (body["act"]["id"],)).fetchone()
    assert row[0] == "{}" and row[1] is None
    assert row[2] == world["caller"] and row[3] is True and row[4] == "AMBER"
    secret = tf.secret_json()
    assert secret not in row[0]
    audited = conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'PERSONA_ACT_QUEUED' "
        "AND object_id = %s", (body["act"]["id"],)).fetchone()[0]
    assert audited == 1


def test_the_collector_runs_the_routes_own_code_and_the_console_reads_the_outcome(
        conn, api, world):
    ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    counters = _drain(conn, api)
    assert counters["claimed"] == 1 and counters["done"] == 1, counters
    assert "join" not in api.factory.methods()
    assert api.factory.proxies[-1]["username"].endswith(f"~act.{world['persona']}")
    seen = api.client.get(f"{API}/acts/{act_id}", headers=world["hdr"])
    assert seen.status_code == 200, seen.text
    out = seen.json()
    assert out["act"]["status"] == "DONE" and out["problem"] is None
    assert out["body"]["member"] is True
    assert out["body"]["chat"]["source_id"] == str(ch["source"])
    stored = _act(conn, act_id)["result"]["body"]
    assert "chat" not in stored, "the chat's view is read again, not kept"
    listed = api.client.get(f"{API}/acts", headers=world["hdr"]).json()
    assert act_id in [a["id"] for a in listed["acts"]]
    assert listed["inline"] is False
    member = conn.execute("SELECT member_since_observed IS NOT NULL FROM "
                          "collect.telegram_chat WHERE source_id = %s",
                          (ch["source"],)).fetchone()[0]
    assert member is True


def test_a_double_click_is_one_act(conn, api, world):
    ch, first = _queue_membership(conn, api, world)
    again = api.client.post(f"{TG}/chats/{ch['source']}/membership", headers=world["hdr"])
    assert again.status_code == 202
    assert again.json()["act"]["id"] == first.json()["act"]["id"]


def test_a_refusal_is_the_routes_own_status_and_sentence(conn, api, world):
    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    conn.execute("UPDATE collect.collection_account SET status = 'BURNED', "
                 "burn_reason = 'a test burn' WHERE id = %s", (world["persona"],))
    r = api.client.post(f"{TG}/chats/{ch['source']}/membership", headers=world["hdr"])
    act_id = r.json()["act"]["id"]
    counters = _drain(conn, api)
    assert counters["refused"] == 1, counters
    out = api.client.get(f"{API}/acts/{act_id}", headers=world["hdr"]).json()
    assert out["act"]["status"] == "REFUSED"
    assert out["problem"]["status"] == 409
    assert "BURNED" in out["problem"]["detail"] or "burn" in out["problem"]["detail"]
    assert api.factory.methods() == []


# --- what the collector asks again ------------------------------------------------

def test_an_act_whose_session_ended_is_not_run(conn, api, world):
    from noctornal_api import persona_acts

    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    conn.execute("UPDATE iam.session SET revoked_at = now() WHERE user_id = %s",
                 (world["caller"],))
    counters = _drain(conn, api)
    assert counters["refused"] == 1, counters
    act = _act(conn, act_id)
    assert act["status"] == "REFUSED"
    assert act["result"]["problem"]["detail"] == persona_acts.SESSION_ENDED
    assert api.factory.methods() == []


def test_the_collector_asks_the_global_gate_again(conn, api, world):
    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    conn.execute("DELETE FROM iam.user_role WHERE user_id = %s", (world["caller"],))
    counters = _drain(conn, api)
    assert counters["refused"] == 1, counters
    problem = _act(conn, act_id)["result"]["problem"]
    assert problem["status"] == 403 and "missing global permission" in problem["detail"]
    denied = conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'AUTHZ_DENIED' "
        "AND actor_id = %s", (world["caller"],)).fetchone()[0]
    assert denied >= 1
    assert api.factory.methods() == []


def test_a_join_whose_second_factor_went_stale_in_the_queue_is_refused(
        conn, api, world, monkeypatch):
    from noctornal_api.http import deps

    ch = _member_chat(conn, world, peer_type="MEGAGROUP", username="auto",
                      access_hash=55)
    api.telegram(tp.fixture_for(ch["spec"], world["uid"]), allow_join=True)
    r = api.client.post(f"{TG}/chats/{ch['source']}/join", headers=world["hdr"],
                        json={"acknowledge_overt": True, "note": "for the operation now"})
    assert r.status_code == 202, r.text
    monkeypatch.setattr(deps, "STEP_UP_FRESHNESS", timedelta(0))
    counters = _drain(conn, api)
    assert counters["refused"] == 1, counters
    problem = _act(conn, r.json()["act"]["id"])["result"]["problem"]
    assert problem["status"] == 403 and "re-authentication" in problem["detail"]
    assert "join" not in api.factory.methods()


def test_an_act_now_above_the_askers_ceiling_is_hidden_and_not_run(conn, api, world):
    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'GREEN' WHERE id = %s",
                 (world["caller"],))
    assert api.client.get(f"{API}/acts/{act_id}", headers=world["hdr"]).status_code == 404
    counters = _drain(conn, api)
    assert counters["refused"] == 1, counters
    assert _act(conn, act_id)["result"]["problem"]["status"] == 403
    assert api.factory.methods() == []


def test_another_person_cannot_see_or_cancel_an_act(conn, api, world):
    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    _other, email = h.user(conn, P, clearance="RED", roles=("COLLECTOR",))
    other = h.auth(h.session(conn, email))
    assert api.client.get(f"{API}/acts/{act_id}", headers=other).status_code == 404
    assert api.client.post(f"{API}/acts/{act_id}/cancel", headers=other).status_code == 404
    assert act_id not in [a["id"] for a in
                          api.client.get(f"{API}/acts", headers=other).json()["acts"]]


# --- waiting, expiry, a dead collector, a busy persona ---------------------------

def _insert(conn, world, ch, key=None, **cols):
    """A row the guard allows an owner to write, as an act the API queued
    some time ago would stand. `key` is the dedupe key of the ask it stands
    for; by default one that matches no ask."""
    from noctornal_api.persona_acts import dedupe_key

    values = {"kind": "TELEGRAM_MEMBERSHIP", "status": "PENDING",
              "requested_at": "now() - interval '2 hours'",
              "expires_at": "now() - interval '1 hour'", "claimed_at": "NULL"}
    values.update(cols)
    return conn.execute(
        f"""INSERT INTO collect.persona_act
               (kind, source_id, classification, params, dedupe_key, requested_by,
                session_id, requested_at, expires_at, status, claimed_at)
            VALUES (%s, %s, 'AMBER', '{{}}'::jsonb, %s, %s, NULL,
                    {values['requested_at']}, {values['expires_at']}, %s,
                    {values['claimed_at']})
            RETURNING id""",
        (values["kind"], ch["source"],
         key or dedupe_key("X", None, {"n": uuid.uuid4().hex}),
         world["caller"], values["status"])).fetchone()[0]


def _insert_live(conn, world, kind, params, *, source_id=None):
    """A live act as the API would have queued it just now, with the
    caller's own session, written by the owner (the queue's own columns,
    nothing the request role could not also write)."""
    from psycopg.types.json import Jsonb

    from noctornal_api.persona_acts import dedupe_key

    sid = conn.execute("SELECT id FROM iam.session WHERE user_id = %s",
                       (world["caller"],)).fetchone()[0]
    return conn.execute(
        """INSERT INTO collect.persona_act
               (kind, source_id, classification, params, dedupe_key, requested_by,
                session_id, mfa_satisfied_at, requested_at, not_before, expires_at)
           SELECT %s, %s, 'AMBER', %s, %s, %s, %s, t, t, t,
                  t + interval '15 minutes'
             FROM (SELECT clock_timestamp() AS t) AS now_
           RETURNING id""",
        (kind, source_id, Jsonb(params), dedupe_key(kind, source_id, params),
         world["caller"], sid)).fetchone()[0]


def test_an_act_nobody_started_in_time_expires_and_never_runs_late(conn, api, world):
    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    act_id = _insert(conn, world, ch)
    counters = _drain(conn, api)
    assert counters["expired"] >= 1 and counters["claimed"] == 0, counters
    act = _act(conn, act_id)
    assert act["status"] == "EXPIRED" and act["result"]["problem"]["status"] == 409
    assert "Ask again" in act["result"]["problem"]["detail"]
    assert api.factory.methods() == []


def test_an_act_a_dead_collector_left_running_fails_and_is_never_repeated(
        conn, api, world):
    from noctornal_api import persona_acts

    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    # Asked two hours ago with an hour to start (the window's own cap), and
    # claimed an hour ago by a collector that has not been heard of since.
    act_id = _insert(conn, world, ch, status="RUNNING",
                     claimed_at="now() - interval '1 hour'")
    counters = _drain(conn, api)
    assert counters["stale"] >= 1 and counters["claimed"] == 0, counters
    act = _act(conn, act_id)
    assert act["status"] == "FAILED"
    assert act["result"]["problem"]["detail"] == persona_acts.OUTCOME_UNKNOWN
    assert api.factory.methods() == []


def test_a_busy_persona_puts_the_act_back_rather_than_refusing_it(conn, api, world):
    from noctornal_api.collection import _PERSONA_LOCK
    from noctornal_api.db import connect

    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    other = connect()
    try:
        other.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))",
                      (f"{_PERSONA_LOCK}:{world['persona']}",))
        counters = _drain(conn, api)
        assert counters["requeued"] == 1, counters
    finally:
        other.close()
    act = _act(conn, act_id)
    assert act["status"] == "PENDING" and act["attempts"] == 1
    later = conn.execute("SELECT not_before > clock_timestamp() FROM "
                         "collect.persona_act WHERE id = %s", (act_id,)).fetchone()[0]
    assert later is True
    assert api.factory.methods() == []


def test_a_pending_act_is_cancelled_and_a_finished_one_cannot_be(conn, api, world):
    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    out = api.client.post(f"{API}/acts/{act_id}/cancel", headers=world["hdr"])
    assert out.status_code == 200 and out.json()["act"]["status"] == "CANCELLED"
    again = api.client.post(f"{API}/acts/{act_id}/cancel", headers=world["hdr"])
    assert again.status_code == 409
    assert _drain(conn, api)["claimed"] == 0


def test_a_finished_act_is_a_record(conn, api, world):
    import psycopg

    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    _drain(conn, api)
    for sql in ("UPDATE collect.persona_act SET status = 'FAILED' WHERE id = %s",
                "UPDATE collect.persona_act SET params = '{\"x\": 1}' WHERE id = %s",
                "DELETE FROM collect.persona_act WHERE id = %s"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute(sql, (act_id,))
    assert _act(conn, act_id)["status"] == "DONE"


def test_the_route_answers_the_finished_act_when_the_collector_is_quick(
        conn, api, world, monkeypatch):
    """The bounded wait: an act finished inside it is answered as the route
    always answered. A stand-in collector finishes it during the wait."""
    from noctornal_api import persona_acts

    monkeypatch.setenv("NOCTORNAL_ACT_WAIT_SECONDS", "5")
    real_wait = persona_acts.wait

    def collector_then_wait(c, act_id, **kw):
        _drain(conn, api)
        return real_wait(c, act_id, **kw)

    monkeypatch.setattr(persona_acts, "wait", collector_then_wait)
    _ch, r = _queue_membership(conn, api, world)
    assert r.status_code == 200, r.text
    assert r.json()["member"] is True and "chat" in r.json()


def test_poll_now_of_a_persona_source_is_an_act_and_a_feed_is_not(conn, api, world):
    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"])
    h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                persona_id=world["persona"], source_ids=[ch["source"]])
    api.telegram(tp.fixture_for(ch["spec"], world["uid"],
                                tp.messages(1, 3, sender=700000001)))
    r = api.client.post(f"{API}/sources/{ch['source']}/run", headers=world["hdr"], json={})
    assert r.status_code == 202, r.text
    assert r.json()["act"]["kind"] == "SOURCE_POLL"
    runs = conn.execute("SELECT count(*) FROM collect.collection_run WHERE source_id = %s",
                        (ch["source"],)).fetchone()[0]
    assert runs == 0, "the API polled nothing"
    counters = _drain(conn, api)
    assert counters["done"] == 1, counters
    out = api.client.get(f"{API}/acts/{r.json()['act']['id']}", headers=world["hdr"]).json()
    assert out["body"]["status"] in ("OK", "PARTIAL"), out
    assert out["body"]["run_id"]


# --- the vault ----------------------------------------------------------------------

def test_a_process_without_the_persona_key_cannot_open_a_persona_credential(
        conn, world, monkeypatch):
    from noctornal_api.collection import PersonaUnavailable, PersonaVault

    monkeypatch.delenv("NOCTORNAL_PERSONA_KEK")
    with pytest.raises(PersonaUnavailable, match="NOCTORNAL_PERSONA_KEK is not set"):
        with PersonaVault(conn).lease(world["persona"], actor_id=None, purpose="t"):
            pass
    monkeypatch.setenv("NOCTORNAL_PERSONA_KEK", "AQEB" * 10 + "AQE=")
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv("NOCTORNAL_COLLECTOR", raising=False)
    with pytest.raises(PersonaUnavailable, match="collector alone"):
        with PersonaVault(conn).lease(world["persona"], actor_id=None, purpose="t"):
            pass


def test_a_credential_sealed_before_the_split_is_refused_by_name_and_then_moved(
        conn, world):
    from noctornal_api.collection import PersonaUnavailable, PersonaVault
    from noctornal_api.security import envelope, persona_envelope
    from noctornal_api.security.persona_sealed import (
        move_and_rewrap,
        sealed_before_split,
    )

    secret = tf.secret_json(session="moved-session-string-0001")
    blob, key_id = envelope.encrypt(secret)
    conn.execute("UPDATE collect.collection_account SET secret_ciphertext = %s, "
                 "secret_key_id = %s WHERE id = %s", (blob, key_id, world["persona"]))
    assert sealed_before_split(conn) >= 1
    with pytest.raises(PersonaUnavailable) as refused:
        with PersonaVault(conn).lease(world["persona"], actor_id=None, purpose="t"):
            pass
    assert persona_envelope.MOVE_COMMAND in str(refused.value)
    # The whole column is visited; rows another run left under a key this
    # process does not hold are counted and left, so only this row is judged.
    report = move_and_rewrap(conn)
    assert report.recovered >= 1
    kid = conn.execute("SELECT secret_key_id FROM collect.collection_account "
                       "WHERE id = %s", (world["persona"],)).fetchone()[0]
    assert kid == persona_envelope.active_key_id()
    with PersonaVault(conn).lease(world["persona"], actor_id=None, purpose="t") as lease:
        assert lease.value == secret


def test_the_rewrap_script_reports_and_moves_persona_credentials(
        conn, world, monkeypatch, capsys):
    from noctornal_api.security import envelope

    sys.path.insert(0, str(ROOT / "scripts"))
    import rewrap_secrets

    blob, key_id = envelope.encrypt(tf.secret_json(session="script-moved-0002"))
    conn.execute("UPDATE collect.collection_account SET secret_ciphertext = %s, "
                 "secret_key_id = %s WHERE id = %s", (blob, key_id, world["persona"]))
    monkeypatch.setattr(sys, "argv", ["rewrap_secrets.py", "--persona"])
    assert rewrap_secrets.main() in (0, 1)
    report = capsys.readouterr().out
    assert "sealed before the split" in report and "--apply" in report
    monkeypatch.setattr(sys, "argv", ["rewrap_secrets.py", "--persona", "--apply"])
    rewrap_secrets.main()
    out = capsys.readouterr().out
    assert "moved" in out
    kid = conn.execute("SELECT secret_key_id FROM collect.collection_account "
                       "WHERE id = %s", (world["persona"],)).fetchone()[0]
    assert kid.startswith("persona:")
    assert tf.secret_json(session="script-moved-0002") not in out


# --- the collector entry point and the register ------------------------------------

def test_the_collector_runs_one_pass_and_its_poll_child(conn, api, world, capsys):
    sys.path.insert(0, str(ROOT / "scripts"))
    import collector

    _ch, r = _queue_membership(conn, api, world)
    started = []

    class Child:
        def wait(self):
            started.append(True)
            return 0

    rc = collector.main(["--once"], conn=conn, start_poll=Child,
                        adapters=api.registry, transport_factory=api.factory)
    out = capsys.readouterr().out
    assert rc == 0, out
    assert started == [True]
    assert "acts claimed=1 done=1" in out
    assert "collection_poll exit=0" in out
    assert _act(conn, r.json()["act"]["id"])["status"] == "DONE"
    assert world["email"] not in out and str(world["persona"]) not in out


def test_the_collector_refuses_to_start_without_the_persona_key(monkeypatch, capsys):
    sys.path.insert(0, str(ROOT / "scripts"))
    import collector

    monkeypatch.delenv("NOCTORNAL_PERSONA_KEK")
    assert collector.main(["--once"], conn=object()) == 2
    assert "NOCTORNAL_PERSONA_KEK" in capsys.readouterr().out


def _beat(conn, instance, *, age_s=0, sampled=0, unopenable=0, problem=None):
    """A collector's heartbeat as one that started `age_s` ago and has not
    been seen since would have left it."""
    from noctornal_api import persona_acts
    from noctornal_api.security.persona_sealed import RingVerdict

    persona_acts.heartbeat_start(conn, instance, RingVerdict(
        ("persona:v1",), sampled, unopenable, problem))
    conn.execute("UPDATE collect.collector_heartbeat SET seen_at = "
                 "clock_timestamp() - make_interval(secs => %s) WHERE instance = %s",
                 (age_s, instance))


def test_the_register_reports_the_split(conn, monkeypatch):
    from noctornal_api import persona_acts, readiness
    from noctornal_api.security import persona_envelope, persona_sealed

    assert "collector_split" in readiness.CHECK_NAMES
    assert "collector_split" not in readiness.BLOCKING_CHECKS
    conn.execute("DELETE FROM collect.collector_heartbeat")
    facts = {"pending": 0, "running": 0, "oldest_pending_s": None,
             "failed_last_day": 0, "last_done_at": None}
    monkeypatch.setattr(persona_acts, "queue_facts", lambda _c: dict(facts))
    monkeypatch.setattr(persona_sealed, "sealed_before_split", lambda _c: 0)
    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", "1")
    inline = readiness.check("collector_split", conn)
    assert inline.ok and "inline mode" in inline.evidence
    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", "0")
    monkeypatch.delenv("NOCTORNAL_PERSONA_KEK")
    # An empty queue and no collector that was ever seen is RED, not green:
    # the state of an upgrade without collector.env, where nothing is
    # pending because nothing can be asked and nothing is polled either.
    never = readiness.check("collector_split", conn)
    assert not never.ok and "no collector has ever started" in never.evidence
    assert "no scheduled poll runs at all" in never.evidence
    assert "feeds no persona reads" in never.evidence
    assert "collector.env" in never.action
    # Seen lately, with a ring that opened what it sampled: green.
    _beat(conn, f"{P}live", sampled=3)
    split = readiness.check("collector_split", conn)
    assert split.ok and "holds no persona key" in split.evidence, split
    assert "a collector was seen" in split.evidence
    # Seen, but not for twenty minutes: red, with how long.
    _beat(conn, f"{P}live", age_s=1200, sampled=3)
    gone = readiness.check("collector_split", conn)
    assert not gone.ok and "no collector has been seen for 20 minutes" in gone.evidence
    assert "collector" in gone.action
    # Seen, with a ring that opened none of what it sampled: red, by name,
    # and the action says how to give it the key that sealed them.
    _beat(conn, f"{P}live", sampled=3, unopenable=3,
          problem="the persona key with id 'persona:v1' does not open this persona's credential")
    wrong = readiness.check("collector_split", conn)
    assert not wrong.ok and "did not open 3 of the 3 persona credentials" in wrong.evidence
    assert persona_acts.COLLECTOR_ACTION_KEY in wrong.action
    # A collector that is seen but not draining.
    _beat(conn, f"{P}live", sampled=3)
    facts.update(pending=2, oldest_pending_s=600.0)
    stuck = readiness.check("collector_split", conn)
    assert not stuck.ok and "no collector is draining" in stuck.evidence
    assert "collector" in stuck.action
    facts.update(pending=0, oldest_pending_s=None)
    monkeypatch.setattr(persona_sealed, "sealed_before_split", lambda _c: 3)
    legacy = readiness.check("collector_split", conn)
    assert not legacy.ok and "3 persona credentials are" in legacy.evidence
    assert persona_envelope.MOVE_COMMAND in legacy.action


def test_a_production_api_holding_the_key_is_red_on_the_register(conn, monkeypatch):
    from noctornal_api import persona_acts, readiness
    from noctornal_api.security import persona_sealed

    monkeypatch.setattr(persona_acts, "queue_facts", lambda _c: {
        "pending": 0, "running": 0, "oldest_pending_s": None,
        "failed_last_day": 0, "last_done_at": None})
    monkeypatch.setattr(persona_sealed, "sealed_before_split", lambda _c: 0)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    held = readiness.check("collector_split", conn)
    assert not held.ok and "only the collector holds" in held.evidence
    assert "collector.env" in held.action
    assert os.environ["NOCTORNAL_PERSONA_KEK"] not in held.evidence + held.action


# --- the idempotency key names the source (verify:g38 blocker, 2026-10-03) ---------

def test_the_dedupe_key_names_the_source_the_kind_and_the_parameters():
    from noctornal_api.persona_acts import dedupe_key

    a, b = uuid.uuid4(), uuid.uuid4()
    assert dedupe_key("K", a, {"x": 1}) == dedupe_key("K", a, {"x": 1})
    assert dedupe_key("K", a, {"x": 1}) != dedupe_key("K", b, {"x": 1})
    assert dedupe_key("K", None, {}) != dedupe_key("K", a, {})
    assert dedupe_key("K", a, {"x": 1}) != dedupe_key("L", a, {"x": 1})
    assert dedupe_key("K", a, {"x": 1}) != dedupe_key("K", a, {"x": 2})


def _acts_of(conn, world):
    return conn.execute(
        "SELECT id, source_id FROM collect.persona_act WHERE requested_by = %s "
        "ORDER BY requested_at", (world["caller"],)).fetchall()


def test_a_membership_check_of_another_chat_is_its_own_act(conn, api, world):
    """Before the fix the second ask was answered with the FIRST act while it
    was live: nothing was queued for chat B, and the console showed A's
    outcome as B's."""
    a, first = _queue_membership(conn, api, world)
    b, second = _queue_membership(conn, api, world)
    assert first.status_code == 202 and second.status_code == 202
    first_id, second_id = first.json()["act"]["id"], second.json()["act"]["id"]
    assert first_id != second_id
    assert first.json()["act"]["source_id"] == str(a["source"])
    assert second.json()["act"]["source_id"] == str(b["source"])
    assert len(_acts_of(conn, world)) == 2
    # The same chat again is still one act.
    again = api.client.post(f"{TG}/chats/{a['source']}/membership", headers=world["hdr"])
    assert again.json()["act"]["id"] == first_id
    assert len(_acts_of(conn, world)) == 2


def test_a_join_of_another_chat_with_the_same_note_is_its_own_act(conn, api, world):
    note = {"acknowledge_overt": True, "note": "for the operation now"}
    first_chat = _member_chat(conn, world, peer_type="MEGAGROUP", username="auto",
                              access_hash=55)
    second_chat = _member_chat(conn, world, peer_type="MEGAGROUP", username="auto",
                               access_hash=56)
    api.telegram(tp.fixture_for(first_chat["spec"], world["uid"]), allow_join=True)
    one = api.client.post(f"{TG}/chats/{first_chat['source']}/join",
                          headers=world["hdr"], json=note)
    two = api.client.post(f"{TG}/chats/{second_chat['source']}/join",
                          headers=world["hdr"], json=note)
    assert one.status_code == 202 and two.status_code == 202
    assert one.json()["act"]["id"] != two.json()["act"]["id"]
    assert two.json()["act"]["source_id"] == str(second_chat["source"])
    same = api.client.post(f"{TG}/chats/{first_chat['source']}/join",
                           headers=world["hdr"], json=note)
    assert same.json()["act"]["id"] == one.json()["act"]["id"]


def test_poll_now_of_another_source_is_its_own_act(conn, api, world):
    sources = []
    for _ in range(2):
        ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"])
        h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                    persona_id=world["persona"], source_ids=[ch["source"]])
        sources.append(ch)
    api.telegram(tp.fixture_for(sources[0]["spec"], world["uid"]))
    ids = []
    for ch in sources:
        r = api.client.post(f"{API}/sources/{ch['source']}/run", headers=world["hdr"],
                            json={})
        assert r.status_code == 202, r.text
        assert r.json()["act"]["source_id"] == str(ch["source"])
        ids.append(r.json()["act"]["id"])
    assert ids[0] != ids[1]
    again = api.client.post(f"{API}/sources/{sources[0]['source']}/run",
                            headers=world["hdr"], json={})
    assert again.json()["act"]["id"] == ids[0]


# --- what is refused at the door and never queued (verify:g38 major) ---------------

INVITE = "AbCdEfGhIjKlMnOpQrSt"


def _chat_body(world, ref, **over):
    body = {"persona_id": str(world["persona"]), "ref": ref, "name": f"{P}chat",
            "classification": "AMBER", "access_mode": "PUBLIC_READ"}
    body.update(over)
    return body


def _stored_by(conn, world, needle):
    """Acts this caller asked for whose parameters carry `needle`. Scoped to
    the caller because the queue's rows are never deleted: an earlier run's
    own rows (the hostile-params test writes one on purpose) stay for ever."""
    return conn.execute("SELECT count(*) FROM collect.persona_act "
                        "WHERE requested_by = %s AND params::text LIKE %s",
                        (world["caller"], f"%{needle}%")).fetchone()[0]


@pytest.mark.parametrize("inline", ["0", "1"])
def test_an_invite_link_is_refused_at_the_door_and_never_written(
        conn, api, world, monkeypatch, inline):
    """A private invite link is a bearer join credential the product
    refuses to take, and the queue's rows can never be deleted: it must not
    reach the table in the queued mode, nor in the inline one (which used
    to answer 400 after the same hash was already stored)."""
    from noctornal_api import telegram

    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", inline)
    api.telegram(tp.fixture_for({"peer_type": "CHANNEL", "peer_id": tp.rand_id(),
                                 "access_hash": 9, "username": "unused_name",
                                 "title": "x", "is_member": False}, world["uid"]))
    for ref in (f"https://t.me/+{INVITE}", f"t.me/joinchat/{INVITE}"):
        r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                            json=_chat_body(world, ref))
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == telegram.INVITE_SENTENCE
    assert _stored_by(conn, world, INVITE) == 0
    assert _acts_of(conn, world) == []
    assert api.factory.transports == []


def test_a_bad_reference_a_public_basic_group_and_an_offline_deployment_are_cheap_400s(
        conn, api, world, monkeypatch):
    """The collector being down must not delay a typo: each is answered by
    the route, and nothing is queued."""
    from noctornal_api import telegram

    api.telegram(tp.fixture_for({"peer_type": "CHANNEL", "peer_id": tp.rand_id(),
                                 "access_hash": 9, "username": "unused_name",
                                 "title": "x", "is_member": False}, world["uid"]))
    for ref, mode, words in (("1300000001", "PUBLIC_READ", "ambiguous"),
                             ("not a chat", "PUBLIC_READ", ""),
                             ("g:1234567", "PUBLIC_READ", "Basic groups are never public")):
        r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                            json=_chat_body(world, ref, access_mode=mode))
        assert r.status_code == 400, (ref, r.text)
        assert words in r.json()["detail"]
    monkeypatch.setattr(telegram, "client_available",
                        lambda: (False, "The Telegram library is not installed."))
    offline = api.client.post(f"{TG}/chats", headers=world["hdr"],
                              json=_chat_body(world, "@some_channel_name"))
    assert offline.status_code == 409
    assert "library is not installed" in offline.json()["detail"]
    assert _acts_of(conn, world) == []


def test_only_the_reference_as_understood_is_queued_and_asked_again_it_is_one_act(
        conn, api, world):
    from noctornal_api.telegram import parse_chat_reference

    api.telegram(tp.fixture_for({"peer_type": "CHANNEL", "peer_id": tp.rand_id(),
                                 "access_hash": 9, "username": "some_channel_1",
                                 "title": "x", "is_member": False}, world["uid"]))
    ids = set()
    for typed in ("https://t.me/Some_Channel_1", "@Some_Channel_1", "t.me/some_channel_1"):
        r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                            json=_chat_body(world, typed))
        assert r.status_code == 202, r.text
        ids.add(r.json()["act"]["id"])
    assert len(ids) == 1, "the same chat, typed three ways, is one act"
    stored = conn.execute("SELECT params FROM collect.persona_act WHERE id = %s",
                          (next(iter(ids)),)).fetchone()[0]
    assert stored["ref"] == "@some_channel_1"
    for typed in ("https://t.me/Some_Channel_1", "c:1234567", "-1001234567",
                  "g:7654321", "-7654321"):
        from noctornal_api.telegram_service import normal_reference

        parsed = parse_chat_reference(typed)
        assert parse_chat_reference(normal_reference(parsed)) == parsed, typed


# --- an act is its own twin only while it is live (verify:g38 minor) --------------

def test_an_expired_act_is_not_the_answer_to_the_same_ask_again(conn, api, world):
    from noctornal_api.persona_acts import dedupe_key

    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    key = dedupe_key("TELEGRAM_MEMBERSHIP", ch["source"], {})
    old = _insert(conn, world, ch, key=key)
    r = api.client.post(f"{TG}/chats/{ch['source']}/membership", headers=world["hdr"])
    assert r.status_code == 202, r.text
    assert r.json()["act"]["id"] != str(old), "the dead act was answered again"
    assert _act(conn, old)["status"] == "EXPIRED"
    assert _act(conn, r.json()["act"]["id"])["status"] == "PENDING"


def test_an_act_a_dead_runner_left_running_does_not_swallow_every_ask_in_inline_mode(
        conn, api, world, monkeypatch):
    from noctornal_api.persona_acts import dedupe_key

    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    key = dedupe_key("TELEGRAM_MEMBERSHIP", ch["source"], {})
    stale = _insert(conn, world, ch, key=key, status="RUNNING",
                    requested_at="now() - interval '5 hours'",
                    expires_at="now() - interval '4 hours 30 minutes'",
                    claimed_at="now() - interval '5 hours'")
    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", "1")
    r = api.client.post(f"{TG}/chats/{ch['source']}/membership", headers=world["hdr"])
    assert r.status_code == 200, r.text
    assert r.json()["member"] is True
    assert _act(conn, stale)["status"] == "FAILED"


def test_a_double_click_while_the_first_act_is_live_is_still_one_act_in_a_race(
        conn, api, world):
    """The partial unique index is the last word: two submits in a row for
    one live act answer one act, and a unique violation is never a 500."""
    from noctornal_api import persona_acts

    ch = _member_chat(conn, world)
    asked = dict(user_id=world["caller"], session_id=None, mfa_at=None,
                 kind="TELEGRAM_MEMBERSHIP", params={}, classification="AMBER",
                 source_id=ch["source"])
    one = persona_acts.submit(conn, **asked)
    two = persona_acts.submit(conn, **asked)
    assert one["id"] == two["id"]


# --- what the collector asks again, once more (verify:g38 vacuous tests) ----------

def test_an_act_for_a_session_idle_past_its_timeout_is_not_run(conn, api, world):
    from noctornal_api import persona_acts
    from noctornal_api.security.sessions import IDLE_TIMEOUT

    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    conn.execute("UPDATE iam.session SET last_seen_at = now() - %s - interval "
                 "'1 minute' WHERE user_id = %s", (IDLE_TIMEOUT, world["caller"]))
    counters = _drain(conn, api)
    assert counters["refused"] == 1, counters
    assert _act(conn, act_id)["result"]["problem"]["detail"] == persona_acts.SESSION_ENDED
    assert api.factory.methods() == []


def test_the_collector_asks_the_readiness_register_again(conn, api, world, monkeypatch):
    """The fixture holds the register green so a route may queue; a check
    that turned red while the act waited refuses it when it runs."""
    from noctornal_api.http.routers import collection as router

    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    monkeypatch.setattr(router, "blocking_failures",
                        lambda _c: ["security_officer_present"])
    counters = _drain(conn, api)
    assert counters["refused"] == 1, counters
    problem = _act(conn, act_id)["result"]["problem"]
    assert problem["status"] == 409
    assert "security_officer_present" in problem["detail"]
    assert api.factory.methods() == []


def test_an_authority_revoked_while_the_act_waited_refuses_it(conn, api, world):
    from noctornal_api.collection_authority import CollectionAuthorityService

    ch = tp.chat(conn, P, persona_id=world["persona"], resolved_by=world["recorder"],
                 access_mode="MEMBER", peer_type="CHAT")
    view = h.authority(conn, recorder=world["recorder"], confirmer=world["confirmer"],
                       persona_id=world["persona"], source_ids=[ch["source"]],
                       scope="MEMBER_READ", member_ref="COVERT-2026-41")
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    r = api.client.post(f"{TG}/chats/{ch['source']}/membership", headers=world["hdr"])
    assert r.status_code == 202, r.text
    CollectionAuthorityService(conn, None).revoke(
        view["id"], revoked_by=world["recorder"], by_role="record",
        reason="withdrawn by the issuer while the act waited", clearance="RED")
    counters = _drain(conn, api)
    assert counters["refused"] == 1, counters
    assert _act(conn, r.json()["act"]["id"])["status"] == "REFUSED"
    assert api.factory.methods() == []


def test_hostile_params_in_the_queue_fail_that_act_cleanly_and_the_pass_goes_on(
        conn, api, world, caplog):
    """The queue's own check bounds what a row may carry, and a compromised
    API could queue anything: an act with parameters missing fails with the
    fixed sentence and a class name in the log, one carrying an invite link
    is refused by create's own check, and the next act still runs."""
    from noctornal_api import persona_acts, telegram

    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    bare = _insert_live(conn, world, "TELEGRAM_RESOLVE", {})
    invite = _insert_live(conn, world, "TELEGRAM_RESOLVE", {
        "persona_id": str(world["persona"]), "ref": f"https://t.me/+{INVITE}",
        "name": f"{P}chat", "classification": "AMBER",
        "default_reliability": "F", "access_mode": "PUBLIC_READ",
        "poll_interval_s": 1800, "jitter_pct": 25, "max_rps": 0.2})
    good = _insert_live(conn, world, "TELEGRAM_MEMBERSHIP", {}, source_id=ch["source"])
    caplog.set_level("DEBUG")
    counters = _drain(conn, api)
    assert (counters["claimed"], counters["failed"], counters["refused"],
            counters["done"]) == (3, 1, 1, 1), counters
    assert _act(conn, bare)["result"]["problem"]["detail"] == persona_acts.FAILED_SENTENCE
    refused = _act(conn, invite)
    assert refused["status"] == "REFUSED"
    assert refused["result"]["problem"]["detail"] == telegram.INVITE_SENTENCE
    assert _act(conn, good)["status"] == "DONE"
    assert INVITE not in caplog.text and world["email"] not in caplog.text


def test_a_forged_future_dated_act_is_not_claimed_before_its_time(conn, api, world):
    """The request role writes requested_at, so the claim does not trust it:
    an act dated ahead waits for its own time, and persona_act_window caps
    how long any act can live (test_rls_persona_act_pg)."""
    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    ahead = _insert(conn, world, ch, requested_at="now() + interval '30 minutes'",
                    expires_at="now() + interval '50 minutes'")
    counters = _drain(conn, api)
    assert counters["claimed"] == 0, counters
    assert _act(conn, ahead)["status"] == "PENDING"


# --- the collector's loop, its stop and its heartbeat (verify:g38) ----------------

class _Child:
    """A poll child: never exits by itself; a stop terminates it, and one
    that will not stop is killed."""

    def __init__(self, stubborn=False):
        self.stubborn = stubborn
        self.terminated = self.killed = False
        self.returncode = None

    def poll(self):
        return None if not (self.terminated and not self.stubborn) else 0

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        import subprocess

        if self.stubborn and not self.killed:
            raise subprocess.TimeoutExpired("collection_poll", timeout)
        return 0


def test_drain_claims_no_further_act_once_asked_to_stop(conn, api, world):
    _a, _ = _queue_membership(conn, api, world)
    _b, second = _queue_membership(conn, api, world)
    asked = {"n": 0}

    def stop_after_the_first():
        asked["n"] += 1
        return asked["n"] > 1

    counters = _drain(conn, api, should_stop=stop_after_the_first)
    assert counters["claimed"] == 1, counters
    assert _act(conn, second.json()["act"]["id"])["status"] == "PENDING"


def test_the_collector_serves_beats_and_stops_on_its_flag(conn, api, world, capsys,
                                                         monkeypatch):
    import threading

    sys.path.insert(0, str(ROOT / "scripts"))
    import collector
    from noctornal_api import persona_acts

    _ch, r = _queue_membership(conn, api, world)
    stop = threading.Event()
    kids = []

    def start_poll():
        kid = _Child()
        kids.append(kid)
        stop.set()                      # the SIGTERM lands while the child runs
        return kid

    beats = []
    real_beat = persona_acts.heartbeat
    monkeypatch.setattr(persona_acts, "heartbeat",
                        lambda c, i: beats.append(i) or real_beat(c, i))
    ticks = iter(range(0, 10_000, 40))  # every look at the clock is 40 s on
    rc = collector.main(["--poll-every", "300", "--wait", "0.01"], conn=conn,
                        start_poll=start_poll, adapters=api.registry,
                        transport_factory=api.factory, stop=stop,
                        clock=lambda: next(ticks))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert _act(conn, r.json()["act"]["id"])["status"] == "DONE"
    assert kids and kids[0].terminated, "the poll child is stopped with the loop"
    assert beats, "the heartbeat moved while it served"
    row = conn.execute("SELECT sampled, unopenable, key_ids FROM "
                       "collect.collector_heartbeat WHERE instance = %s",
                       (persona_acts.instance_name(),)).fetchone()
    assert row is not None and row[1] == 0 and row[2] == ["persona:v1"]
    assert "persona ring keys=persona:v1" in out and "unopenable=0" in out
    assert world["email"] not in out and str(world["persona"]) not in out


def test_a_collector_already_told_to_stop_claims_nothing(conn, api, world):
    import threading

    sys.path.insert(0, str(ROOT / "scripts"))
    import collector

    _ch, r = _queue_membership(conn, api, world)
    stop = threading.Event()
    stop.set()
    rc = collector.main(["--poll-every", "0"], conn=conn, adapters=api.registry,
                        transport_factory=api.factory, stop=stop)
    assert rc == 0
    assert _act(conn, r.json()["act"]["id"])["status"] == "PENDING"


def test_a_poll_child_that_will_not_stop_is_killed():
    sys.path.insert(0, str(ROOT / "scripts"))
    import collector

    stubborn = _Child(stubborn=True)
    collector._stop_child(stubborn)
    assert stubborn.terminated and stubborn.killed
    polite = _Child()
    collector._stop_child(polite)
    assert polite.terminated and not polite.killed
    collector._stop_child(None)


def test_the_collectors_stop_grace_covers_the_longest_act_and_the_child():
    import re

    from noctornal_api import telegram

    sys.path.insert(0, str(ROOT / "scripts"))
    import collector

    text = (ROOT / "infra" / "production" / "compose.yml").read_text(encoding="utf-8")
    start = text.index("\n  collector:\n")
    block = text[start:start + 6000].split("\n  lab-", 1)[0]
    grace = re.search(r"(?m)^    stop_grace_period: (\d+)s$", block)
    assert grace, "the collector service names its stop_grace_period"
    # A Telegram poll's whole session (the longest act), the child's
    # wind-down, and the backstop past the session that is waited for.
    needed = (telegram.TELEGRAM_RUN_SECONDS + telegram.BACKSTOP_SECONDS + 20
              + collector.CHILD_STOP_SECONDS)
    assert int(grace.group(1)) >= needed, (grace.group(1), needed)


# --- a key that changed under its id, and nothing that falls back ------------------

def test_a_persona_key_that_changed_under_its_id_is_refused_by_name_and_the_register_says_so(
        conn, api, world, monkeypatch):
    import base64

    from noctornal_api import persona_acts, readiness
    from noctornal_api.security import persona_envelope, persona_sealed

    used = lambda: conn.execute(  # noqa: E731 - a counter, used twice
        "SELECT count(*) FROM audit.event WHERE object_id = %s "
        "AND action = 'PERSONA_USED'", (world["persona"],)).fetchone()[0]
    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    before = used()
    # The collector.env of another deployment: a key of its own under the
    # SAME id the credentials were sealed under.
    other_key = base64.b64encode(b"\x02" * 32).decode()
    monkeypatch.setenv(persona_envelope.KEK_ENV, other_key)
    counters = _drain(conn, api)
    assert counters["refused"] == 1 and counters["failed"] == 0, counters
    problem = _act(conn, act_id)["result"]["problem"]
    assert problem["status"] == 409
    assert "does not open this persona's credential" in problem["detail"]
    assert persona_envelope.RETIRED_ENV in problem["detail"]
    assert "InvalidTag" not in problem["detail"]
    assert api.factory.methods() == []
    assert used() == before, "a use that never happened is not audited"
    # The collector's ring verdict at start reads the same truth ...
    verdict = persona_sealed.ring_verdict(conn)
    assert verdict.unopenable >= 1 and verdict.problem
    assert other_key not in verdict.problem
    # ... and publishes it where the register reads it.
    conn.execute("DELETE FROM collect.collector_heartbeat")
    persona_acts.heartbeat_start(conn, f"{P}ring", verdict)
    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", "0")
    seen = readiness.check("collector_split", conn)
    assert not seen.ok and "persona key ring did not open" in seen.evidence
    assert persona_acts.COLLECTOR_ACTION_KEY in seen.action


def test_every_way_a_persona_credential_can_fail_to_open_is_a_named_refusal(conn, world):
    from noctornal_api.collection import PersonaUnavailable, PersonaVault

    def seal(blob, key_id):
        conn.execute("UPDATE collect.collection_account SET secret_ciphertext = %s, "
                     "secret_key_id = %s WHERE id = %s", (blob, key_id, world["persona"]))

    # An id this ring does not hold, and bytes that are no envelope.
    for blob, key_id, words in ((b"x" * 40, "persona:v9", "persona:v9"),
                                (b"short", "persona:v1", "")):
        seal(blob, key_id)
        with pytest.raises(PersonaUnavailable) as refused:
            with PersonaVault(conn).lease(world["persona"], actor_id=None, purpose="t"):
                pass
        assert words in str(refused.value)
        assert "InvalidTag" not in str(refused.value)


def test_a_credential_under_the_totp_ring_is_never_opened_with_it(conn, world,
                                                                  monkeypatch):
    """Nothing falls back to the TOTP ring: its own opener is rigged to
    fail the test if anything in the vault so much as reaches for it."""
    from noctornal_api.collection import PersonaUnavailable, PersonaVault
    from noctornal_api.security import envelope

    blob, key_id = envelope.encrypt(tf.secret_json(session="before-the-split-0003"))
    conn.execute("UPDATE collect.collection_account SET secret_ciphertext = %s, "
                 "secret_key_id = %s WHERE id = %s", (blob, key_id, world["persona"]))

    def fell_back(*_a, **_k):
        raise AssertionError("the persona vault reached for the TOTP ring")

    for name in ("decrypt", "can_open", "open_with", "rewrap"):
        monkeypatch.setattr(envelope, name, fell_back)
    used = conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s "
                        "AND action = 'PERSONA_USED'", (world["persona"],)).fetchone()[0]
    with pytest.raises(PersonaUnavailable):
        with PersonaVault(conn).lease(world["persona"], actor_id=None, purpose="t"):
            pass
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s "
                        "AND action = 'PERSONA_USED'",
                        (world["persona"],)).fetchone()[0] == used


def test_the_rewrap_script_without_the_totp_key_refuses_by_name_and_does_not_crash(
        conn, world, monkeypatch, capsys):
    """verify:g38: with a row still sealed before the split and no TOTP key,
    --persona used to die in the inventory with a RuntimeError traceback
    and exit 1; the refusal is exit 2 and names the ring."""
    from noctornal_api.security import envelope

    sys.path.insert(0, str(ROOT / "scripts"))
    import rewrap_secrets

    blob, key_id = envelope.encrypt(tf.secret_json(session="needs-the-totp-key-0004"))
    conn.execute("UPDATE collect.collection_account SET secret_ciphertext = %s, "
                 "secret_key_id = %s WHERE id = %s", (blob, key_id, world["persona"]))
    monkeypatch.delenv("NOCTORNAL_TOTP_KEK")
    for argv in (["--persona"], ["--persona", "--apply"]):
        monkeypatch.setattr(sys, "argv", ["rewrap_secrets.py", *argv])
        assert rewrap_secrets.main() == 2, argv
        err = capsys.readouterr().err
        assert "TOTP key ring" in err and "collector" in err
        assert "Traceback" not in err
    kid = conn.execute("SELECT secret_key_id FROM collect.collection_account "
                       "WHERE id = %s", (world["persona"],)).fetchone()[0]
    assert kid == key_id, "nothing was moved"


def test_an_act_the_sweep_already_failed_is_not_audited_finished_twice(conn, api, world):
    """verify:g38 minor (2026-10-03): the stale sweep failed an act that was
    still executing; when it came back, `_finish` matched no row yet wrote a
    FINISHED event with the outcome it computed, so the log said DONE where
    the row said FAILED."""
    from noctornal_api import persona_acts

    _ch, r = _queue_membership(conn, api, world)
    act_id = r.json()["act"]["id"]
    claimed = persona_acts._claim_next(conn, "collector:late")
    assert claimed is not None and str(claimed["id"]) == act_id
    conn.execute("UPDATE collect.persona_act SET claimed_at = clock_timestamp() "
                 "- interval '1 hour' WHERE id = %s", (act_id,))
    assert persona_acts.sweep(conn)[1] >= 1
    after = persona_acts._finish(conn, claimed, "DONE", body={"member": True})
    assert after["status"] == "FAILED"
    events = conn.execute("SELECT detail->>'status' FROM audit.event WHERE "
                          "action = 'PERSONA_ACT_FINISHED' AND object_id = %s",
                          (act_id,)).fetchall()
    assert events == [("FAILED",)], events
    assert _act(conn, act_id)["result"]["problem"]["detail"] == persona_acts.OUTCOME_UNKNOWN


def test_adding_two_different_chats_is_two_acts(conn, api, world):
    """The key names the parameters as well as the source: two chats asked
    for in a row are two acts, the same chat typed again is one."""
    api.telegram(tp.fixture_for({"peer_type": "CHANNEL", "peer_id": tp.rand_id(),
                                 "access_hash": 9, "username": "first_chat_one",
                                 "title": "x", "is_member": False}, world["uid"]))
    ids = []
    for ref in ("@first_chat_one", "@second_chat_two"):
        r = api.client.post(f"{TG}/chats", headers=world["hdr"],
                            json=_chat_body(world, ref))
        assert r.status_code == 202, r.text
        ids.append(r.json()["act"]["id"])
    assert ids[0] != ids[1]
    again = api.client.post(f"{TG}/chats", headers=world["hdr"],
                            json=_chat_body(world, "@first_chat_one"))
    assert again.json()["act"]["id"] == ids[0]


def test_a_real_sigterm_stops_the_collector_cleanly(conn, api, world):
    """The handler main() installs, reached by a real signal: the loop ends,
    the poll child is stopped, the pass returns 0 and the previous handler
    comes back."""
    import signal
    import threading

    sys.path.insert(0, str(ROOT / "scripts"))
    import collector

    kids = []

    def start_poll():
        kids.append(_Child())
        return kids[-1]

    previous = signal.getsignal(signal.SIGTERM)
    timer = threading.Timer(1.0, lambda: signal.raise_signal(signal.SIGTERM))
    timer.start()
    try:
        rc = collector.main(["--poll-every", "300", "--wait", "0.05"],
                            start_poll=start_poll, adapters=api.registry,
                            transport_factory=api.factory)
    finally:
        timer.cancel()
        signal.signal(signal.SIGTERM, previous)
    assert rc == 0
    assert kids and kids[0].terminated


def test_the_collector_writes_its_heartbeat_at_start_and_not_only_when_one_is_due(
        conn, api, world):
    """A clock that never reaches the 30 second mark: the row is the start
    beat's alone, with the ring verdict it reached."""
    import threading

    sys.path.insert(0, str(ROOT / "scripts"))
    import collector
    from noctornal_api import persona_acts

    stop = threading.Event()

    def start_poll():
        stop.set()
        return _Child()

    rc = collector.main(["--poll-every", "300", "--wait", "0.01"], conn=conn,
                        start_poll=start_poll, adapters=api.registry,
                        transport_factory=api.factory, stop=stop, clock=lambda: 0.0)
    assert rc == 0
    row = conn.execute("SELECT key_ids, sampled >= unopenable FROM "
                       "collect.collector_heartbeat WHERE instance = %s",
                       (persona_acts.instance_name(),)).fetchone()
    assert row == (["persona:v1"], True)


def test_a_stop_during_an_act_claims_no_second_one_in_the_collectors_own_pass(
        conn, api, world):
    """The stop flag is asked before every claim INSIDE a pass, not only
    between passes: the second act waits for the next collector."""
    import threading

    sys.path.insert(0, str(ROOT / "scripts"))
    import collector

    _a, first = _queue_membership(conn, api, world)
    _b, second = _queue_membership(conn, api, world)
    stop = threading.Event()
    real = api.factory

    def stopping_factory(secret, route, fingerprint, *, proxy):
        stop.set()                      # SIGTERM arrives while the first act runs
        return real(secret, route, fingerprint, proxy=proxy)

    rc = collector.main(["--poll-every", "0", "--wait", "0.01"], conn=conn,
                        adapters=api.registry, transport_factory=stopping_factory,
                        stop=stop)
    assert rc == 0
    states = {_act(conn, r.json()["act"]["id"])["status"] for r in (first, second)}
    assert "PENDING" in states and len(states) == 2, states


# --- mutants the first round's tests let live (verify:g38, 2026-10-03) ----------
#
# Dropping the session ownership pin, and adding the parameters to what an
# act shows, each left every test above green. These two, and the forged
# label beside them, are the verifier's scratch tests adopted.

_FORGE = """
INSERT INTO collect.persona_act
   (kind, source_id, classification, params, dedupe_key, requested_by,
    session_id, mfa_satisfied_at, requested_at, not_before, expires_at)
SELECT %(kind)s, %(src)s, %(cls)s::core.tlp, %(params)s::jsonb, %(key)s, %(who)s,
       %(sess)s, now(), t, t, t + interval '10 minutes'
  FROM (SELECT clock_timestamp() AS t) x
RETURNING id"""


def _session_id(conn, uid):
    return conn.execute(
        "SELECT id FROM iam.session WHERE user_id = %s ORDER BY issued_at DESC LIMIT 1",
        (uid,)).fetchone()[0]


def test_an_acts_session_must_belong_to_the_person_who_asked(conn, api, world):
    """An act that names user B as the asker and user A's live session is
    refused: the collector's re-check pins the session to the asker, so a
    session id alone never lends one person's standing to another."""
    from noctornal_api import persona_acts

    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    other, other_email = h.user(conn, P, clearance="RED", roles=("COLLECTOR",))
    h.session(conn, other_email, fresh=True)
    # The control first: the same act with its OWN session runs, so the
    # refusal below is the pin and not a broken fixture.
    own = conn.execute(_FORGE, {
        "kind": "TELEGRAM_MEMBERSHIP", "src": ch["source"], "cls": "AMBER",
        "params": "{}", "key": "d" * 64, "who": other,
        "sess": _session_id(conn, other)}).fetchone()[0]
    counters = _drain(conn, api)
    assert _act(conn, own)["status"] == "DONE", (_act(conn, own), counters)
    sent = list(api.factory.methods())
    forged = conn.execute(_FORGE, {
        "kind": "TELEGRAM_MEMBERSHIP", "src": ch["source"], "cls": "AMBER",
        "params": "{}", "key": "a" * 64, "who": other,
        "sess": _session_id(conn, world["caller"])}).fetchone()[0]
    counters = _drain(conn, api)
    act = _act(conn, forged)
    assert act["status"] == "REFUSED", (act, counters)
    assert act["result"]["problem"]["detail"] == persona_acts.SESSION_ENDED
    assert api.factory.methods() == sent, "nothing new reached Telegram"


def test_a_forged_low_label_over_a_higher_chat_is_not_run(conn, api, world):
    """An act dated CLEAR by a caller whose ceiling is GREEN, over a chat
    the caller may not see, does not run: the label on the row is the
    asker's to forge, so the chat's own visibility is asked again."""
    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    low, low_email = h.user(conn, P, clearance="GREEN", roles=("COLLECTOR",))
    h.session(conn, low_email, fresh=True)
    control = conn.execute(_FORGE, {
        "kind": "TELEGRAM_MEMBERSHIP", "src": ch["source"], "cls": "CLEAR",
        "params": "{}", "key": "b" * 64, "who": world["caller"],
        "sess": _session_id(conn, world["caller"])}).fetchone()[0]
    counters = _drain(conn, api)
    assert _act(conn, control)["status"] == "DONE", (_act(conn, control), counters)
    before = list(api.factory.methods())
    forged = conn.execute(_FORGE, {
        "kind": "TELEGRAM_MEMBERSHIP", "src": ch["source"], "cls": "CLEAR",
        "params": "{}", "key": "c" * 64, "who": low,
        "sess": _session_id(conn, low)}).fetchone()[0]
    counters = _drain(conn, api)
    assert _act(conn, forged)["status"] in ("REFUSED", "FAILED"), (
        _act(conn, forged), counters)
    assert api.factory.methods() == before, "nothing new reached Telegram for the low caller"


def test_what_an_act_shows_never_carries_its_parameters_or_its_session(conn, api, world):
    """The module and the routes promise it; a field added to public()
    would put a join note, a reason or a chat reference in every list."""
    from noctornal_api import persona_acts

    marker = "PARAM-MARKER-4471 do not show"
    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    queued = api.client.post(f"{TG}/chats/{ch['source']}/join", headers=world["hdr"],
                             json={"acknowledge_overt": True, "note": marker})
    assert queued.status_code == 202, queued.text
    act_id = queued.json()["act"]["id"]
    stored = _act(conn, act_id)["params"]
    assert stored == {"note": marker}, "the parameters are in the row, as they must be"
    seen = [queued.text,
            api.client.get(f"{API}/acts/{act_id}", headers=world["hdr"]).text,
            api.client.get(f"{API}/acts", headers=world["hdr"]).text]
    for text in seen:
        assert "PARAM-MARKER" not in text, text
        assert '"params"' not in text and "session_id" not in text, text
    shown = persona_acts.public({
        "id": uuid.uuid4(), "kind": "TELEGRAM_JOIN", "status": "PENDING",
        "source_id": None, "classification": "AMBER", "requested_at": None,
        "claimed_at": None, "finished_at": None, "expires_at": None,
        "attempts": 0, "result": None, "params": {"note": marker},
        "session_id": uuid.uuid4()})
    assert "params" not in shown and "session_id" not in shown
    assert marker not in repr(shown)


#: U+FFFD, built rather than typed so no editor or tool can turn the escape
#: into the character itself.
_REPLACEMENT = chr(0xFFFD)


def test_a_nul_in_free_text_is_cleaned_and_never_a_500(conn, api, world):
    """U+0000 in a join note or a member reason reached the act's INSERT and
    raised UntranslatableCharacter, so the route answered 500 (verify:g38
    minor, 2026-10-03). It is replaced by U+FFFD, one for one, the act is
    queued, and nothing reaches Telegram."""
    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    text = "a valid note\x00 with a nul"
    wanted = text.replace("\x00", _REPLACEMENT)
    joined = api.client.post(f"{TG}/chats/{ch['source']}/join", headers=world["hdr"],
                             json={"acknowledge_overt": True, "note": text})
    assert joined.status_code == 202, joined.text
    assert _act(conn, joined.json()["act"]["id"])["params"] == {"note": wanted}
    marked = api.client.post(f"{TG}/chats/{ch['source']}/member", headers=world["hdr"],
                             json={"reason": text})
    assert marked.status_code == 202, marked.text
    assert _act(conn, marked.json()["act"]["id"])["params"]["reason"] == wanted
    assert api.factory.methods() == []


def test_a_lone_surrogate_in_free_text_is_a_422_and_queues_nothing(conn, api, world):
    """The verifier saw an error here, which was httpx failing to encode the
    request; sent as the JSON escape a real client sends, the server answers
    422 (pydantic refuses it) and no act is written."""
    ch = _member_chat(conn, world)
    api.telegram(tp.fixture_for(dict(ch["spec"], is_member=True), world["uid"]))
    before = conn.execute("SELECT count(*) FROM collect.persona_act WHERE "
                          "requested_by = %s", (world["caller"],)).fetchone()[0]
    json_header = {**world["hdr"], "content-type": "application/json"}
    for route, body in (
            ("join", b'{"acknowledge_overt": true, "note": "a valid note \\ud800 lone"}'),
            ("member", b'{"reason": "a valid reason \\ud800 lone"}')):
        r = api.client.post(f"{TG}/chats/{ch['source']}/{route}", headers=json_header,
                            content=body)
        assert r.status_code == 422, (route, r.status_code, r.text)
    after = conn.execute("SELECT count(*) FROM collect.persona_act WHERE "
                         "requested_by = %s", (world["caller"],)).fetchone()[0]
    assert after == before


def test_every_free_text_model_of_the_act_routes_cleans_a_nul():
    """The create and rebind routes carry the same text fields; the models
    are what the routes share, so they are held without a session."""
    from noctornal_api.http.routers import collection_telegram as r

    dirty = "text\x00 and\x00 here"
    clean = dirty.replace("\x00", _REPLACEMENT)
    assert r.JoinBody(acknowledge_overt=True, note=dirty).note == clean
    assert r.ReasonBody(reason=dirty).reason == clean
    assert r.RebindBody(persona_id=uuid.uuid4(), reason=dirty).reason == clean
    assert r.ChatCreate(persona_id=uuid.uuid4(), ref="@somechat", name=dirty,
                        classification="AMBER").name == clean
    # The field's own limits still apply: replacement is one for one.
    with pytest.raises(ValueError):
        r.JoinBody(acknowledge_overt=True, note="\x00" * 9)
