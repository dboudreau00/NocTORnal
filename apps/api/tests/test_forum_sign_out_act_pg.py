"""A forum persona's stop is signed out by the collector, the one process
that opens the sealed session (the authenticated forum path merged with the
persona vault split, decision 174, 2026-10-03). DATABASE_URL-gated.

test_forum_member.py holds the stop in development's inline mode, where the
API runs the act itself. These tests turn the inline mode OFF, as
production is: the persona's stop route queues a `FORUM_SIGN_OUT` act and
waits a bounded time, the collector's `persona_acts.drain` runs it (the
session is opened, and the board signed out of, in the collector's thread
and never the request's), and the stop clears the sealed session whatever
happened. With no collector running the act is cancelled, the stop goes on,
the sealed session is cleared by the stop alone, and the answer says the
board's own sign-out was not reached.
"""
from __future__ import annotations

# Fixtures imported from the suites whose worlds these tests reuse.
# ruff: noqa: F811

import os
import threading
import time

import pytest

import collection_helpers as h
from test_forum_member import (  # noqa: F401  (fixtures, the world builder)
    _session_row,
    _svc,
    _world,
    conn,
    registry,
    stub,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")

P = "test-fmbr-"


@pytest.fixture(autouse=True)
def the_queue(monkeypatch):
    """The queue, not the inline mode, and the blocking readiness checks
    out of the way (they are the register's, not this test's)."""
    from noctornal_api.http.routers import collection as router

    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", "0")
    monkeypatch.setattr(router, "blocking_failures", lambda _c: [])


def _acts(conn, persona):
    return conn.execute(
        """SELECT kind, status, claimed_by, params ->> 'persona_id'
             FROM collect.persona_act WHERE kind = 'FORUM_SIGN_OUT'
              AND params ->> 'persona_id' = %s ORDER BY requested_at""",
        (str(persona),)).fetchall()


def _stop(client, conn, persona, email):
    return client.post(
        f"/api/v1/collection/personas/{persona}/status",
        headers=h.auth(h.session(conn, email)),
        json={"status": "BURNED", "reason": "a person burns this persona"})


def test_the_collector_signs_the_persona_out_and_the_request_never_opens_the_session(
        conn, stub, monkeypatch):
    from noctornal_api import forum_session, persona_acts
    from noctornal_api.db import SystemPurpose, connect_system

    monkeypatch.setenv("NOCTORNAL_ACT_WAIT_SECONDS", "25")
    w = _world(conn, stub, "xenforo")
    client, _app = h.client()
    uid, email = h.user(conn, P, roles=("COLLECTOR",))
    opened_in: list[str] = []
    real_open = forum_session.open_sessions

    def watching(c, persona_id):
        opened_in.append(threading.current_thread().name)
        return real_open(c, persona_id)

    monkeypatch.setattr(forum_session, "open_sessions", watching)
    collector_conn = connect_system(SystemPurpose.PERSONA_ACTS)

    def collector():
        # What scripts/collector.py does between acts: drain the queue.
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            counters = persona_acts.drain(
                collector_conn, instance="collector:test-fmbr",
                adapters=registry(), limit=5)
            if counters["claimed"]:
                return
            time.sleep(0.1)

    thread = threading.Thread(target=collector, name="the-collector", daemon=True)
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        assert w["board"].sessions and w["board"].logouts == 0
        opened_in.clear()
        thread.start()
        answer = _stop(client, conn, w["persona"], email)
        thread.join(30)
        assert answer.status_code == 200, answer.text
        assert answer.json()["status"] == "BURNED"
        assert "signed out of its forum" in answer.json()["forum_sign_out"]
        assert w["board"].logouts == 1 and w["board"].sessions == {}
        assert _session_row(conn, w["persona"]) == (False, None, None)
        # One act, run by the collector and not by the request.
        acts = _acts(conn, w["persona"])
        assert [(a[0], a[1]) for a in acts] == [("FORUM_SIGN_OUT", "DONE")]
        assert acts[0][2] == "collector:test-fmbr"
        assert opened_in and set(opened_in) == {"the-collector"}, \
            "the sealed session was opened outside the collector"
        assert uid
    finally:
        collector_conn.close()
        w["board"].close()


def test_a_red_readiness_register_does_not_hold_back_the_sign_out_of_a_stop(
        conn, stub, monkeypatch):
    """A stop is always allowed (F38) and its route asks no readiness, so
    the sign-out it queues is not refused by the collector for a blocking
    check that turned red either (beta 1 gate 6, 2026-10-07): a burnt
    persona's board session must not stay open because, say, the security
    officer's account was deactivated."""
    from noctornal_api import persona_acts
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.http.routers import collection as router

    monkeypatch.setenv("NOCTORNAL_ACT_WAIT_SECONDS", "25")
    w = _world(conn, stub, "xenforo")
    client, _app = h.client()
    _uid, email = h.user(conn, P, roles=("COLLECTOR",))
    collector_conn = connect_system(SystemPurpose.PERSONA_ACTS)

    def collector():
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if persona_acts.drain(collector_conn, instance="collector:test-fmbr",
                                  adapters=registry(), limit=5)["claimed"]:
                return
            time.sleep(0.1)

    thread = threading.Thread(target=collector, daemon=True)
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        monkeypatch.setattr(router, "blocking_failures",
                            lambda _c: ["security_officer_present"])
        thread.start()
        answer = _stop(client, conn, w["persona"], email)
        thread.join(30)
        assert answer.status_code == 200, answer.text
        assert "signed out of its forum" in answer.json()["forum_sign_out"], answer.json()
        assert w["board"].logouts == 1
        assert [(a[0], a[1]) for a in _acts(conn, w["persona"])] == [
            ("FORUM_SIGN_OUT", "DONE")]
    finally:
        collector_conn.close()
        w["board"].close()


def test_with_no_collector_the_stop_clears_the_session_and_says_the_board_was_not_reached(
        conn, stub, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ACT_WAIT_SECONDS", "0")
    w = _world(conn, stub, "mybb")
    client, _app = h.client()
    uid, email = h.user(conn, P, roles=("COLLECTOR",))
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        assert _session_row(conn, w["persona"])[0] is True
        answer = _stop(client, conn, w["persona"], email)
        assert answer.status_code == 200, answer.text
        assert "not reached" in answer.json()["forum_sign_out"]
        # The board still holds its session: nothing here could reach it.
        assert w["board"].logouts == 0 and w["board"].sessions
        # The guarantee stands without the act: nothing is left sealed.
        assert _session_row(conn, w["persona"]) == (False, None, None)
        # The act was withdrawn rather than left to run against nothing.
        assert [(a[0], a[1]) for a in _acts(conn, w["persona"])] == [
            ("FORUM_SIGN_OUT", "CANCELLED")]
        assert uid
    finally:
        w["board"].close()


def test_a_persona_with_no_session_is_stopped_without_asking_the_collector(
        conn, stub, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ACT_WAIT_SECONDS", "25")
    w = _world(conn, stub, "xenforo")
    client, _app = h.client()
    _uid, email = h.user(conn, P, roles=("COLLECTOR",))
    try:
        assert _session_row(conn, w["persona"])[0] is False
        started = time.monotonic()
        answer = _stop(client, conn, w["persona"], email)
        assert answer.status_code == 200, answer.text
        assert "forum_sign_out" not in answer.json()
        assert _acts(conn, w["persona"]) == []
        assert time.monotonic() - started < 10, "the stop waited for nobody"
    finally:
        w["board"].close()


def test_the_act_kind_is_one_the_queue_accepts_and_the_collector_can_run():
    from noctornal_api import persona_acts

    kind = persona_acts.KINDS["FORUM_SIGN_OUT"]
    assert kind.permissions == (("collection_account.manage", False),)
    # The route's mapping of a refusal answers it too, as a poll's does.
    from noctornal_api.collection import CollectionNotFound

    problem = persona_acts._problem_for("FORUM_SIGN_OUT",
                                        CollectionNotFound("no such persona"))
    assert problem["status"] == 404


# --- migration 0165 --------------------------------------------------------------

class _Rollback(Exception):
    """Ends a transaction a test wants undone, DDL and rows included."""


def _migration_0165():
    import importlib.util
    from pathlib import Path

    path = next((Path(__file__).resolve().parents[3] / "db" / "migrations"
                 / "versions").glob("0165_*.py"))
    spec = importlib.util.spec_from_file_location("m0165", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _raw_act(conn, uid, kind, status):
    from noctornal_api.persona_acts import dedupe_key

    finished = "NULL" if status in ("PENDING", "RUNNING") else "clock_timestamp()"
    claimed = "clock_timestamp()" if status != "PENDING" else "NULL"
    return conn.execute(
        f"""INSERT INTO collect.persona_act
               (kind, classification, params, dedupe_key, requested_by,
                requested_at, expires_at, status, claimed_at, finished_at)
            VALUES (%s, 'AMBER', '{{}}'::jsonb, %s, %s, clock_timestamp(),
                    clock_timestamp() + interval '10 minutes', %s,
                    {claimed}, {finished})
            RETURNING id""",
        (kind, dedupe_key("X", None, {"n": str(uid)}), uid, status)).fetchone()[0]


def _kind_check_validated(conn) -> bool:
    return conn.execute(
        "SELECT convalidated FROM pg_constraint WHERE conname = 'persona_act_kind' "
        "AND conrelid = 'collect.persona_act'::regclass").fetchone()[0]


def test_the_downgrade_refuses_work_in_flight_and_keeps_a_finished_record(conn):
    """0165's downgrade: never narrow the check under a sign-out act still
    pending or running; once none is, restore 0156's check, validated when
    no sign-out act is recorded and NOT VALID (keeping the record, which can
    never be deleted) when one is. Everything here is rolled back."""
    import psycopg

    module = _migration_0165()
    uid, _email = h.user(conn, P, roles=("COLLECTOR",))
    if not _recorded(conn):
        # Provable on a database no sign-out act has run on (a fresh one):
        # the restored check is 0156's, validated.
        with pytest.raises(_Rollback):
            with conn.transaction():
                conn.execute(module.DOWNGRADE_SQL)
                assert _kind_check_validated(conn) is True
                raise _Rollback
    with pytest.raises(_Rollback):
        with conn.transaction():
            assert _kind_check_validated(conn) is True
            pending = _raw_act(conn, uid, "FORUM_SIGN_OUT", "PENDING")
            with pytest.raises(psycopg.errors.RaiseException,
                               match="still pending or running"):
                with conn.transaction():
                    conn.execute(module.DOWNGRADE_SQL)
            conn.execute(
                "UPDATE collect.persona_act SET status = 'CANCELLED', "
                "finished_at = clock_timestamp() WHERE id = %s", (pending,))
            conn.execute(module.DOWNGRADE_SQL)
            # A finished sign-out act stays, and the old check is NOT VALID.
            assert _kind_check_validated(conn) is False
            with pytest.raises(psycopg.errors.CheckViolation):
                with conn.transaction():
                    _raw_act(conn, uid, "FORUM_SIGN_OUT", "PENDING")
            # The upgrade restates the wider check, validated.
            conn.execute(module.UPGRADE_SQL)
            assert _kind_check_validated(conn) is True
            raise _Rollback


def _recorded(conn) -> bool:
    """A sign-out act from another test, which can never be deleted."""
    return conn.execute("SELECT EXISTS (SELECT 1 FROM collect.persona_act "
                        "WHERE kind = 'FORUM_SIGN_OUT')").fetchone()[0]


# --- the session's key ---------------------------------------------------------------

def test_a_session_seals_under_the_persona_key_and_moves_with_it(conn, stub, monkeypatch):
    """The jar is sealed under the persona ring, never the TOTP ring; a
    rotation of that ring re-seals it (`reseal_sessions`, which `rewrap_
    secrets.py --persona --apply` runs), and one recorded under the TOTP
    ring, which no release ever wrote, is cleared rather than moved."""
    import base64

    from noctornal_api import forum_session
    from noctornal_api.security import persona_envelope as pe
    from noctornal_api.security.persona_sealed import reseal_sessions

    w = _world(conn, stub, "xenforo")
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        before = _session_row(conn, w["persona"])
        assert before[0] is True and pe.is_persona_key_id(before[1])
        origin = forum_session.origin_key(w["board"].base_url)
        held = forum_session.open_session(conn, w["persona"], origin)
        assert held, "the sealed session opens under the persona ring"
        # The ring turns: a new active key, the old one retired under its id.
        monkeypatch.setenv("NOCTORNAL_PERSONA_KEK_RETIRED",
                           f"{before[1]}={os.environ['NOCTORNAL_PERSONA_KEK']}")
        monkeypatch.setenv("NOCTORNAL_PERSONA_KEK_ID", "persona:g40m-rotated")
        monkeypatch.setenv("NOCTORNAL_PERSONA_KEK",
                           base64.b64encode(os.urandom(32)).decode())
        report, _cleared = reseal_sessions(conn)
        assert report.rewrapped >= 1
        after = _session_row(conn, w["persona"])
        assert after[1] == "persona:g40m-rotated"
        assert forum_session.open_session(conn, w["persona"], origin) == held
        # A session under a TOTP ring id is not moved: it is cleared.
        conn.execute("UPDATE collect.collection_account SET session_key_id = 'env:v1' "
                     "WHERE id = %s", (w["persona"],))
        _report, cleared = reseal_sessions(conn)
        assert cleared >= 1
        assert _session_row(conn, w["persona"]) == (False, None, None)
    finally:
        w["board"].close()


def test_no_process_without_the_persona_key_can_open_a_session(conn, stub, monkeypatch):
    """The API holds no persona key: the jar is database-only for it. It
    cannot open one, and says so rather than reading it as no session."""
    from noctornal_api import forum_session
    from noctornal_api.security import persona_envelope as pe

    w = _world(conn, stub, "mybb")
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        origin = forum_session.origin_key(w["board"].base_url)
        monkeypatch.delenv("NOCTORNAL_PERSONA_KEK")
        with pytest.raises(pe.PersonaKeyError):
            forum_session.open_session(conn, w["persona"], origin)
        # Clearing opens nothing, so the API's stop path works without it.
        assert forum_session.clear_session(conn, w["persona"]) is True
    finally:
        w["board"].close()
