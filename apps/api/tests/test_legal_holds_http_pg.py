"""Legal holds: what a hold names, what the console is told, and what a hold
says about a purge it waited for (2026-10-08).

- hold rows name no exhibit: a hold or a lift wrote its audit row with
  `object_id` NULL and `/audit/events` returns no `detail`, so an officer
  could not tell which exhibit was held. The row names the exhibit, and the
  case for a case-level hold.
- no console control for a hold: the register and the case record say whether
  the reader may place and lift one (`may_hold`), carry whether the case is
  held, and give a hold's reason to the people who place and lift holds and
  to nobody else.
- a hold cannot reach into a delete in flight: the hold response reports what
  the purge destroyed while it waited, counted over what the holder may see.

Accounts `g44t-*` (the prefix `g44_support` cleans up); the object store is
`g44_support.VersionedStore`, so nothing is written to the dev bucket.
"""
from __future__ import annotations

import threading
from dataclasses import replace

import pytest

import g44_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

API = "/api/v1"
REASON = "Court order 2026-0042: preserve, informant identity at issue"
AUTHORITY = "g79 retention schedule 2026-10"


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    limits = dict(LIMITS)
    # A lift has a burst of three, and these tests lift more often than that.
    limits["retention.lift"] = replace(limits["retention.lift"],
                                       quota=1000, burst=1000)
    app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    return TestClient(app, raise_server_exceptions=False)


def _hold(client, headers, exhibit, on=True, reason=REASON):
    return client.post(f"{API}/retention/legal-hold", headers=headers,
                       json={"evidence_id": str(exhibit), "on": on,
                             "reason": reason})


def _case_hold(client, headers, case_id, on=True, reason=REASON):
    return client.post(f"{API}/retention/cases/{case_id}/legal-hold",
                       headers=headers, json={"on": on, "reason": reason})


def _rows(conn, action, case_id):
    return conn.execute(
        "SELECT object_type, object_id, outcome FROM audit.event "
        "WHERE action = %s AND case_id = %s ORDER BY seq",
        (action, case_id)).fetchall()


# --- hold rows name no exhibit ---------------------------------------------

def test_a_hold_and_a_lift_name_the_exhibit_in_the_audit_row(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    officer = g.user(conn, "RED", roles=("SECURITY_OFFICER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, "AMBER")
    headers = g.token(conn, boss)

    assert _hold(client, headers, exhibit).status_code == 200
    assert _hold(client, headers, exhibit, on=False,
                 reason="order discharged, g79").status_code == 200

    assert _rows(conn, "LEGAL_HOLD_APPLIED", case_id) == [
        ("evidence", exhibit, "SUCCESS")]
    assert _rows(conn, "LEGAL_HOLD_LIFTED", case_id) == [
        ("evidence", exhibit, "SUCCESS")]

    # And the officer's own view of the log, which returns no `detail`, says
    # which exhibit.
    r = client.get(f"{API}/audit/events", headers=g.token(conn, officer),
                   params={"case_id": str(case_id)})
    assert r.status_code == 200, r.text
    held = [e for e in r.json()["events"] if e["action"] == "LEGAL_HOLD_APPLIED"]
    assert [e["object_id"] for e in held] == [str(exhibit)]
    assert "detail" not in held[0]


def test_a_case_hold_and_a_refused_lift_name_the_case(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, lead, "CASE_OWNER")
    s.exhibit(conn, case_id, boss, "RED")           # above the lead

    assert _case_hold(client, g.token(conn, lead), case_id).status_code == 200
    refused = _case_hold(client, g.token(conn, lead), case_id, on=False,
                         reason="lifting this on my own authority")
    assert refused.status_code == 400, refused.text
    assert _case_hold(client, g.token(conn, boss), case_id, on=False,
                      reason="order discharged, g79").status_code == 200

    assert _rows(conn, "LEGAL_HOLD_APPLIED", case_id) == [
        ("case", case_id, "SUCCESS")]
    assert _rows(conn, "LEGAL_HOLD_LIFT_REFUSED", case_id) == [
        ("case", case_id, "DENIED")]
    assert _rows(conn, "LEGAL_HOLD_LIFTED", case_id) == [
        ("case", case_id, "SUCCESS")]


# --- no console control for a hold -----------------------------------------

def _register(client, headers, case_id):
    r = client.get(f"{API}/cases/{case_id}/evidence", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def test_the_register_offers_the_control_to_whoever_may_place_a_hold(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    # A lead on this case only: the hold route asks for the global role too.
    case_only = g.user(conn, "RED", roles=())
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, analyst, "ANALYST")
    s.assign(conn, case_id, case_only, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, "AMBER")
    assert _hold(client, g.token(conn, boss), exhibit).status_code == 200

    mine = _register(client, g.token(conn, boss), case_id)
    assert mine["may_hold"] is True
    [row] = mine["items"]
    assert row["legal_hold"] is True and row["legal_hold_reason"] == REASON

    for who in (analyst, case_only):
        theirs = _register(client, g.token(conn, who), case_id)
        assert theirs["may_hold"] is False
        [row] = theirs["items"]
        assert row["legal_hold"] is True
        assert row["legal_hold_reason"] is None, (
            "a hold's text went to somebody who does not place holds")
        assert REASON not in str(theirs)


def test_the_offer_does_not_wait_for_a_fresh_sign_in(conn, client):
    """The control is drawn for a lead whose second factor has lapsed, and
    the act asks for the sign-in itself, as Export does."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.exhibit(conn, case_id, boss, "AMBER")
    _, raw = s.session(conn, boss, mfa=False)
    stale = {"Authorization": f"Bearer {raw}"}
    assert _register(client, stale, case_id)["may_hold"] is True


def test_the_case_record_says_whether_it_is_held_and_who_may_say_why(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, analyst, "ANALYST")
    boss_h, analyst_h = g.token(conn, boss), g.token(conn, analyst)

    before = client.get(f"{API}/cases/{case_id}", headers=boss_h).json()
    assert before["legal_hold"] is False and before["may_hold"] is True
    assert before["legal_hold_reason"] is None

    assert _case_hold(client, boss_h, case_id).status_code == 200
    mine = client.get(f"{API}/cases/{case_id}", headers=boss_h).json()
    assert mine["legal_hold"] is True
    assert mine["legal_hold_reason"] == REASON and mine["may_hold"] is True

    theirs = client.get(f"{API}/cases/{case_id}", headers=analyst_h).json()
    assert theirs["legal_hold"] is True and theirs["may_hold"] is False
    assert theirs["legal_hold_reason"] is None
    assert REASON not in str(theirs)

    # A listing draws neither the reason nor the control: it is not where the
    # text a court order rests on is handed to everyone who opens the page.
    [listed] = [c for c in client.get(f"{API}/cases", headers=boss_h).json()
                if c["id"] == str(case_id)]
    assert listed["legal_hold"] is True
    assert listed["legal_hold_reason"] is None and listed["may_hold"] is False

    # The record the console is handed after a correction carries it too.
    patched = client.patch(f"{API}/cases/{case_id}", headers=boss_h,
                           json={"summary": "g79 correction"})
    assert patched.status_code == 200, patched.text
    assert patched.json()["legal_hold"] is True
    assert patched.json()["may_hold"] is True


# --- a hold cannot reach into a delete in flight ---------------------------

def _sweep_and_a_hold_that_waits(conn, *, holder_ceiling, exhibit_class="AMBER"):
    """Run the scheduled sweep of three exhibits in a thread, stop it inside
    the delete of the one it reaches first, and from a second connection place
    a case hold that waits for it. Returns (the hold's answer, the case)."""
    import time

    from noctornal_api.retention import RetentionService

    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    exhibits = [g.lodge(conn, store, case_id, boss, title=f"e{i}",
                        classification=exhibit_class)[0].evidence_id
                for i in range(3)]
    g.age_case(conn, case_id, g.expired())
    first = sorted(exhibits)[0]
    key_first = g.evidence_row(conn, first)[0]
    started, release = threading.Event(), threading.Event()
    outcome: dict = {}

    def stop_in_the_first_delete(key):
        if key == key_first:
            started.set()
            assert release.wait(30)

    store.on_delete = stop_in_the_first_delete

    def sweep():
        c = s.owner_conn()
        try:
            outcome["result"] = RetentionService(c, store).purge_due(
                actor_id=boss, authority=AUTHORITY, case_id=case_id)
        except Exception as exc:  # noqa: BLE001 - reported to the test
            outcome["error"] = exc
        finally:
            c.close()

    def hold():
        c = s.owner_conn()
        try:
            outcome["hold"] = RetentionService(c).set_case_legal_hold(
                case_id, actor_id=boss, on=True, reason=REASON,
                lifter_ceiling=holder_ceiling)
        except Exception as exc:  # noqa: BLE001 - reported to the test
            outcome["hold_error"] = exc
        finally:
            c.close()

    sweeper, holder = threading.Thread(target=sweep), threading.Thread(target=hold)
    sweeper.start()
    try:
        assert started.wait(30), "the sweep never reached the store"
        holder.start()
        time.sleep(0.8)
        assert holder.is_alive(), "the hold did not wait for the exhibit in flight"
    finally:
        release.set()
        sweeper.join(60)
        holder.join(60)
    assert "error" not in outcome, outcome.get("error")
    assert "hold_error" not in outcome, outcome.get("hold_error")
    assert outcome["result"].evidence_purged == 1, "the exhibit in flight went"
    return outcome["hold"], case_id


def test_a_case_hold_says_what_the_purge_destroyed_while_it_waited(conn):
    answer, case_id = _sweep_and_a_hold_that_waits(
        conn, holder_ceiling=("RED", []))
    assert answer["legal_hold"] is True
    assert answer["destroyed_while_waiting"] == {"evidence": 1, "total": 1}
    assert "had already destroyed 1 exhibit" in answer["notice"]
    assert "cannot bring it back" in answer["notice"]
    assert "everything not yet reached is kept" in answer["notice"]
    assert "A purge or a sample rejection in this case was running" in answer["notice"]
    [(detail,)] = conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'LEGAL_HOLD_APPLIED' "
        "AND case_id = %s", (case_id,)).fetchall()
    assert detail["destroyed_while_waiting"] == {"evidence": 1}


def test_the_hold_counts_only_what_the_holder_may_see(conn):
    """The in-flight exhibit is RED and the holder is cleared to AMBER: the
    answer says nothing of it, whatever the case's setting, as the due list
    and the dry run say nothing of an exhibit above the caller."""
    answer, case_id = _sweep_and_a_hold_that_waits(
        conn, holder_ceiling=("AMBER", []), exhibit_class="RED")
    assert answer == {"case_id": str(case_id), "legal_hold": True,
                      "legal_hold_reason": REASON}
    [(detail,)] = conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'LEGAL_HOLD_APPLIED' "
        "AND case_id = %s", (case_id,)).fetchall()
    assert "destroyed_while_waiting" not in detail


def test_a_hold_that_waited_for_nothing_answers_as_it_always_did(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.exhibit(conn, case_id, boss, "AMBER")
    r = _case_hold(client, g.token(conn, boss), case_id)
    assert r.status_code == 200, r.text
    assert r.json() == {"case_id": str(case_id), "legal_hold": True,
                        "legal_hold_reason": REASON}


def test_the_sentence_lists_every_kind_the_purge_took():
    from noctornal_api.retention import _waited_sentence
    said = _waited_sentence({"evidence": 2, "ingest_record": 1, "sample": 1})
    assert "2 exhibits, 1 ingest record and 1 sample" in said
    assert "cannot bring them back" in said
