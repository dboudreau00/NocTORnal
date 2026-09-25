"""The persona gate, persona_session and a persona's polls (2026-09-24).

The six steps (check, lock, hours, authority, pace, route and lease), the
platform's answers recorded on the persona before it is unlocked, the
suspension notifications, the reseal of a moved credential, and the route
token kept out of every stored error. DATABASE_URL-gated; no network.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-b0ps-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _stub(**attrs):
    stub = h.StubAuthorityAdapter(**attrs)
    stub.key = "stubtg"
    stub.source_kinds = frozenset({"TELEGRAM"})
    stub.persona_platform = "TELEGRAM"
    return stub


@pytest.fixture
def world(conn):
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    manager, _ = h.user(conn, P, roles=("COLLECTOR",))
    egress = h.egress_profile(conn, P)
    persona = h.persona(conn, P, egress=egress, secret="tg-session-abcdef-1")
    source = h.source(conn, P, kind="TELEGRAM", parser="stubtg", persona=persona,
                      base_url=None)
    stub = _stub()
    view = h.authority(conn, recorder=recorder, confirmer=confirmer,
                       persona_id=persona, source_ids=[source],
                       adapters=h.adapters(stub))
    return {"recorder": recorder, "confirmer": confirmer, "manager": manager,
            "egress": egress, "persona": persona, "source": source,
            "stub": stub, "authority": view}


def _svc(conn, stub, **kw):
    from noctornal_api.collection import CollectionService
    return CollectionService(conn, h.adapters(stub), **kw)


def _session(conn, world, **kw):
    from noctornal_api.collection import persona_session

    args = dict(actor_id=world["recorder"], clearance="RED", purpose="look up",
                source_id=None, need="PUBLIC_READ", platform="TELEGRAM")
    args.update(kw)
    return persona_session(conn, world["persona"], **args)


def _locked_elsewhere(persona_id):
    from noctornal_api.db import connect

    other = connect()
    got = other.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                        (f"collect.persona:{persona_id}",)).fetchone()[0]
    other.close()
    return not got


# --- the steps ----------------------------------------------------------

def test_an_unusable_persona_is_refused_before_the_lock(conn, world):
    from noctornal_api.collection import BURNED, PersonaUnavailable, PersonaVault

    PersonaVault(conn).set_status(world["persona"], BURNED,
                                  actor_id=world["recorder"], reason="challenged")
    used = len(conn.execute("SELECT 1 FROM audit.event WHERE object_id = %s "
                            "AND action = 'PERSONA_USED'",
                            (world["persona"],)).fetchall())
    with pytest.raises(PersonaUnavailable, match="burnt"):
        with _session(conn, world):
            pass
    assert len(conn.execute("SELECT 1 FROM audit.event WHERE object_id = %s "
                            "AND action = 'PERSONA_USED'",
                            (world["persona"],)).fetchall()) == used


def test_a_hidden_persona_is_not_found_before_the_lock(conn, world):
    from noctornal_api.collection import CollectionNotFound

    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                 (world["source"],))
    with pytest.raises(CollectionNotFound):
        with _session(conn, world, clearance="AMBER"):
            pass


def test_a_second_session_on_one_persona_is_busy(conn, world):
    from noctornal_api.collection import CollectionBusy
    from noctornal_api.db import connect

    other = connect()
    try:
        other.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                      (f"collect.persona:{world['persona']}",))
        with pytest.raises(CollectionBusy):
            with _session(conn, world):
                pass
    finally:
        other.close()


def test_outside_active_hours_the_persona_rests(conn, world):
    from noctornal_api.collection import PersonaGate, PersonaResting

    conn.execute("""UPDATE collect.collection_account
                       SET fingerprint_profile = '{"active_window_utc": "22:00-06:00"}'
                     WHERE id = %s""", (world["persona"],))
    gate = PersonaGate(conn, world["persona"], actor_id=None, clearance=None,
                       purpose="x", source_id=None, need="PUBLIC_READ",
                       platform="TELEGRAM")
    gate.check()
    with pytest.raises(PersonaResting, match="until 22:00 UTC") as caught:
        gate.window(now=datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc))
    assert caught.value.until == datetime(2026, 9, 24, 22, 0, tzinfo=timezone.utc)
    gate.window(now=datetime(2026, 9, 24, 23, 0, tzinfo=timezone.utc))


def test_a_missing_authority_is_refused_after_the_lock_and_the_lock_released(conn):
    from noctornal_api.collection import persona_session
    from noctornal_api.collection_authority import AuthorityMissing

    egress = h.egress_profile(conn, P)
    pid = h.persona(conn, P, egress=egress, secret="no-authority-yet-1")
    with pytest.raises(AuthorityMissing, match="no confirmed authority at all"):
        with persona_session(conn, pid, actor_id=None, clearance=None,
                             purpose="enrol", source_id=None,
                             need="PUBLIC_READ", platform="TELEGRAM"):
            pass
    assert not _locked_elsewhere(pid)


def test_a_persona_authority_with_no_sources_allows_its_acts_and_no_read(conn, world):
    """A new persona could never get its first authority,
    because an authority needed a bound source and a source needed the
    persona's authority to be created. An authority naming the persona and
    no source now allows its own acts, and no poll."""
    from noctornal_api.collection import persona_session
    from noctornal_api.collection_authority import AuthorityMissing

    egress = h.egress_profile(conn, P)
    pid = h.persona(conn, P, egress=egress, secret="fresh-persona-001")
    view = h.authority(conn, recorder=world["recorder"],
                       confirmer=world["confirmer"], persona_id=pid,
                       source_ids=[], adapters=h.adapters(world["stub"]))
    assert view["state"] == "LIVE" and view["targets"] == []
    assert "no read" in view["persona_acts"]
    with persona_session(conn, pid, actor_id=world["manager"], clearance="RED",
                         purpose="enrol", source_id=None, need="PUBLIC_READ",
                         platform="TELEGRAM") as ctx:
        assert ctx.authority.authority_id is not None
        assert ctx.route.context == f"act:{pid}"
    later = h.source(conn, P, kind="TELEGRAM", parser="stubtg", persona=pid,
                     base_url=None)
    with pytest.raises(AuthorityMissing):
        from noctornal_api.collection_authority import CollectionAuthorityService
        CollectionAuthorityService(conn, h.adapters(world["stub"])).require(
            persona_id=pid, source_id=later, need="PUBLIC_READ")


def test_the_confirmer_is_refused_as_the_actor_of_an_act(conn, world):
    from noctornal_api.collection_authority import AuthorityError

    with pytest.raises(AuthorityError, match="does not run the collection"):
        with _session(conn, world, actor_id=world["confirmer"]):
            pass


def test_the_persona_gap_is_waited(conn, world):
    from noctornal_api.collection import persona_session

    conn.execute("UPDATE collect.collection_account SET last_request_at = "
                 "clock_timestamp() WHERE id = %s", (world["persona"],))
    slept = []
    with persona_session(conn, world["persona"], actor_id=world["recorder"],
                         clearance="RED", purpose="x", source_id=None,
                         need="PUBLIC_READ", platform="TELEGRAM", min_gap_s=30,
                         sleep=slept.append):
        pass
    assert slept and 20 < slept[0] <= 30


def test_a_stamp_ahead_of_the_clock_waits_the_whole_gap(conn, world):
    """The database clock stepped back after the last request: the gap is
    waited in full, never skipped (2026-09-25)."""
    from noctornal_api.collection import persona_session

    conn.execute("UPDATE collect.collection_account SET last_request_at = "
                 "clock_timestamp() + interval '5 seconds' WHERE id = %s",
                 (world["persona"],))
    slept = []
    with persona_session(conn, world["persona"], actor_id=world["recorder"],
                         clearance="RED", purpose="x", source_id=None,
                         need="PUBLIC_READ", platform="TELEGRAM", min_gap_s=30,
                         sleep=slept.append):
        pass
    assert slept == [30]


def test_an_unavailable_route_is_refused(conn, world, monkeypatch):
    from noctornal_api import egress
    from noctornal_api.collection import EgressUnavailable
    from noctornal_api.pinned_http import RouteUnavailable

    def refuse(*a, **k):
        raise RouteUnavailable("in production every outbound connection leaves "
                               "through the egress proxy", code="proxy_required")

    monkeypatch.setattr(egress, "route_for", refuse)
    with pytest.raises(EgressUnavailable, match="egress proxy"):
        with _session(conn, world):
            pass
    assert not _locked_elsewhere(world["persona"])


def test_the_lock_is_released_when_the_block_raises(conn, world):
    with pytest.raises(ValueError):
        with _session(conn, world):
            assert _locked_elsewhere(world["persona"])
            raise ValueError("the act failed")
    assert not _locked_elsewhere(world["persona"])


def test_abandoned_work_cools_the_persona_before_the_unlock(conn, world, monkeypatch):
    from noctornal_api.collection import PersonaGate, WorkAbandoned

    seen = {}
    release = PersonaGate.release

    def spying(self):
        seen["hold"] = conn.execute(
            "SELECT machine_hold_reason FROM collect.collection_account "
            "WHERE id = %s", (world["persona"],)).fetchone()[0]
        return release(self)

    monkeypatch.setattr(PersonaGate, "release", spying)
    with pytest.raises(WorkAbandoned):
        with _session(conn, world, adapter=_stub(abandon_cooldown_s=900.0)):
            raise WorkAbandoned("The session outlived its budget.")
    assert seen["hold"] == "ABANDONED"


def test_an_attended_act_answers_the_platforms_wait_with_its_end_in_utc(conn, world):
    """The sentence for a platform's wait carries the end of the wait in
    UTC, which until 2026-09-25 it left out. The act that met the wait and
    the next act, refused at the gate by the live hold, give the same
    answer."""
    from noctornal_api.collection import (
        PersonaUnavailable,
        RateLimited,
        attended_answer,
    )

    with pytest.raises(RateLimited) as caught:
        with _session(conn, world):
            raise RateLimited(600)
    until = conn.execute(
        "SELECT machine_hold_until FROM collect.collection_account WHERE id = %s",
        (world["persona"],)).fetchone()[0].astimezone(timezone.utc)
    expected = (f"The platform asked this persona to wait until "
                f"{until:%Y-%m-%d %H:%M} UTC. Nothing was done.")
    assert attended_answer(caught.value) == (409, expected)
    with pytest.raises(PersonaUnavailable) as again:
        with _session(conn, world):
            pass
    assert attended_answer(again.value) == (409, expected)


def test_abandoned_work_is_answered_with_the_rest_in_minutes(conn, world):
    from noctornal_api.collection import WorkAbandoned, attended_answer

    with pytest.raises(WorkAbandoned) as caught:
        with _session(conn, world, adapter=_stub(abandon_cooldown_s=900.0)):
            raise WorkAbandoned("The session outlived its budget.")
    status, sentence = attended_answer(caught.value)
    assert status == 504
    assert sentence == ("The platform did not answer in time. The persona rests "
                        "for 15 minutes so no second session starts while the "
                        "first may still be open.")


def test_a_stopping_session_opens_a_locked_persona_through_the_stop_context(conn, world):
    from noctornal_api.collection import PersonaVault

    PersonaVault(conn).signal(world["persona"], reason="dup",
                              lock_code="CREDENTIAL_DUPLICATED")
    with _session(conn, world, stopping=True, purpose="log out") as ctx:
        assert ctx.lease.value == "tg-session-abcdef-1"
        assert ctx.route.context == f"stop:{world['persona']}"
        assert ctx.authority is None, "stopping never asks the authority"


def test_the_route_token_is_registered_for_redaction(conn, world, monkeypatch):
    from noctornal_api import egress, egress_policy
    from noctornal_api.collection import redact

    token = "T" * 20 + "0123456789abcdefghijklmn"

    class Provider:
        @staticmethod
        def route_parts(kind, name, **_kw):
            return egress.RouteParts(egress_policy.RoutePolicy(
                kind, any_public=True, admission="proxy"), token)

    monkeypatch.setattr(egress, "_route_provider", lambda: Provider)
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://127.0.0.1:3128")
    with _session(conn, world) as ctx:
        assert ctx.route.proxied
        assert token not in redact(f"socks5 auth failed for {token}")


# --- polls as a persona ------------------------------------------------

def test_the_run_records_persona_egress_and_start_time(conn, world):
    result = _svc(conn, world["stub"]).run_once(world["source"],
                                                actor_id=world["manager"],
                                                clearance="RED")
    row = conn.execute(
        """SELECT collection_account_id, egress_profile_id, started_at,
                  authority_id FROM collect.collection_run WHERE id = %s""",
        (result.run_id,)).fetchone()
    assert result.status == "OK", result.error
    assert row[0] == world["persona"] and row[1] == world["egress"]
    assert row[2] is not None and str(row[3]) == world["authority"]["id"]
    assert world["stub"].last_context.persona.lease.value == ""  # dropped after


def test_run_once_rate_limited_cools_the_persona_and_is_not_a_failure(conn, world):
    from noctornal_api.collection import RateLimited

    def produce(ctx):
        raise RateLimited(300)

    world["stub"].produce = produce
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    hold, failures, due = conn.execute(
        """SELECT a.machine_hold_until, s.consecutive_failures, s.next_due_at
             FROM collect.collection_account a, collect.source s
            WHERE a.id = %s AND s.id = %s""",
        (world["persona"], world["source"])).fetchone()
    assert result.status == "RATE_LIMITED" and failures == 0
    assert hold > datetime.now(timezone.utc) + timedelta(seconds=300)
    assert due >= hold - timedelta(seconds=1)


def test_run_once_suspension_locks_blocks_and_notifies_managers(conn, world):
    from noctornal_api.collection import PersonaSuspended

    def produce(ctx):
        raise PersonaSuspended("The platform revoked the session.",
                               lock_code="CREDENTIAL_REVOKED")

    world["stub"].produce = produce
    result = _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    lock, blocked = conn.execute(
        """SELECT a.machine_lock_code, s.blocked_reason
             FROM collect.collection_account a, collect.source s
            WHERE a.id = %s AND s.id = %s""",
        (world["persona"], world["source"])).fetchone()
    assert result.status == "BLOCKED" and lock == "CREDENTIAL_REVOKED"
    assert blocked == "The persona that reads this source was suspended by its platform."
    notes = conn.execute(
        """SELECT recipient_id, classification::text FROM notify.notification
            WHERE kind = 'PERSONA_SUSPENDED' AND object_id = %s""",
        (world["persona"],)).fetchall()
    assert world["manager"] in {r[0] for r in notes}
    assert {r[1] for r in notes} == {"AMBER"}


def test_a_credential_alert_goes_to_officers_only_urgent_green_and_without_a_handle(conn, world):
    from noctornal_api.collection import PersonaSuspended

    def produce(ctx):
        raise PersonaSuspended("The session is in use elsewhere.",
                               lock_code="CREDENTIAL_DUPLICATED",
                               alert_officers=True)

    world["stub"].produce = produce
    _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    rows = conn.execute(
        """SELECT n.recipient_id, n.priority, n.classification::text, n.body,
                  n.summary
             FROM notify.notification n
            WHERE n.kind = 'PERSONA_CREDENTIAL_ALERT' AND n.object_id = %s""",
        (world["persona"],)).fetchall()
    assert rows and world["confirmer"] in {r[0] for r in rows}
    assert world["manager"] not in {r[0] for r in rows}
    handle = conn.execute("SELECT handle FROM collect.collection_account WHERE id = %s",
                          (world["persona"],)).fetchone()[0]
    for _rid, priority, label, body, summary in rows:
        assert priority == 1 and label == "GREEN"
        assert handle not in body and handle not in summary


def test_a_moved_credential_is_resealed_even_when_the_persist_fails(conn, world):
    from noctornal_api.collection import FetchResult, PersonaVault

    world["stub"].produce = lambda ctx: FetchResult(secret_update="tg-session-moved-2")

    def commit(conn, **kw):
        raise RuntimeError("the adapter's table is gone")

    world["stub"].commit = commit
    with pytest.raises(RuntimeError):
        _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    with PersonaVault(conn).use(world["persona"], actor_id=None, purpose="x") as v:
        assert v == "tg-session-moved-2"


def test_two_sources_on_one_persona_never_poll_at_once(conn, world):
    from noctornal_api.collection import CollectionBusy
    from noctornal_api.db import connect

    other = connect()
    try:
        other.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                      (f"collect.persona:{world['persona']}",))
        with pytest.raises(CollectionBusy, match="persona"):
            _svc(conn, world["stub"]).run_once(world["source"], actor_id=None)
    finally:
        other.close()
    assert not _locked_elsewhere(world["persona"])


def test_a_persona_resting_outside_its_hours_is_held_and_spread_past_the_opening(conn, world):
    from noctornal_api.collection import CollectionService

    now = datetime.now(timezone.utc)
    start = (now + timedelta(hours=2)).strftime("%H:%M")
    end = (now + timedelta(hours=3)).strftime("%H:%M")
    conn.execute(
        """UPDATE collect.collection_account
              SET fingerprint_profile = jsonb_build_object('active_window_utc', %s::text)
            WHERE id = %s""", (f"{start}-{end}", world["persona"]))
    conn.execute("UPDATE collect.source SET jitter_pct = 50, poll_interval_s = 3600 "
                 "WHERE id = %s", (world["source"],))
    svc = CollectionService(conn, h.adapters(world["stub"]))
    held = {s["id"]: s for s in svc.held_sources()}
    assert held[world["source"]]["reason"] == "PERSONA"
    due = conn.execute("SELECT next_due_at FROM collect.source WHERE id = %s",
                       (world["source"],)).fetchone()[0]
    opening = now.replace(second=0, microsecond=0) + timedelta(hours=2)
    assert opening - timedelta(minutes=1) <= due <= opening + timedelta(minutes=31)


def test_one_reading_of_the_schedule_counts_a_resting_source_as_held(conn, world):
    """2026-09-25: the cron read the schedule twice, due
    and then held, and the first reading moves a source resting outside
    its persona's hours past `now`, so the second no longer counted it.
    due_and_held answers both from one reading."""
    from noctornal_api.collection import CollectionService

    now = datetime.now(timezone.utc)
    window = (f"{(now + timedelta(hours=2)):%H:%M}-"
              f"{(now + timedelta(hours=3)):%H:%M}")
    conn.execute(
        """UPDATE collect.collection_account
              SET fingerprint_profile = jsonb_build_object('active_window_utc', %s::text)
            WHERE id = %s""", (window, world["persona"]))
    svc = CollectionService(conn, h.adapters(world["stub"]))
    due, held = svc.due_and_held()
    assert world["source"] in {s["id"] for s in held}
    assert world["source"] not in {s["id"] for s in due}
    # The two-reading shape this replaced: the source was moved by the
    # first reading, so a second one does not see it at all.
    assert world["source"] not in {s["id"] for s in svc.held_sources()}
