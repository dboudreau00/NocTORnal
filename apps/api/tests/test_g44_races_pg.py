"""The purge against a second connection (unit g44, 2026-10-03), the cases
`test_g44_retention_pg.py` leaves out:

- an out-of-schedule purge locks every row and case it names before the
  store is asked to delete any, so a hold entered while it runs waits and is
  then refused as the destroyed exhibit it is, and never acknowledged;
- a case-level hold entered while the scheduled sweep runs waits for the
  exhibit in flight (the sweep claims each in a transaction of its own) and
  is then read by every exhibit the sweep has not reached (Beta 1, C6).

Accounts `g44t-*`; the object store is `g44_support.VersionedStore`.
"""
from __future__ import annotations

import threading

import psycopg
import pytest

import g44_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

AUTHORITY = "g44 races 2026-10"
REASON = "preservation order 2026-17, g44 race test"


def _service(c, store=None):
    from noctornal_api.retention import RetentionService
    return RetentionService(c, store)


def test_a_hold_entered_while_an_early_purge_runs_waits_and_is_then_refused(conn):
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.retention import RetentionError
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    approver = g.user(conn, "RED")
    case_id = g.case(conn, boss)                    # retention 2030: not due
    one, _ = g.lodge(conn, store, case_id, boss)
    two, _ = g.lodge(conn, store, case_id, boss)
    ids = [one.evidence_id, two.evidence_id]
    payload = {"case_id": str(case_id), "evidence_ids": sorted(str(i) for i in ids),
               "authority": AUTHORITY}
    req = ApprovalService(conn).request(
        operation="evidence.purge", case_id=case_id, payload=payload,
        justification="g44 early destruction", requested_by=boss)
    ApprovalService(conn).decide(req.id, decided_by=approver, approve=True)

    started, release = threading.Event(), threading.Event()
    outcome: dict = {}

    def stop_in_the_first_delete(_key):
        if not started.is_set():
            started.set()
            assert release.wait(30)

    store.on_delete = stop_in_the_first_delete

    def purge():
        c = s.owner_conn()
        try:
            outcome["result"] = _service(c, store).purge_out_of_schedule(
                actor_id=boss, authority=AUTHORITY, approval_request_id=req.id,
                case_id=case_id, evidence_ids=ids)
        except Exception as exc:  # noqa: BLE001 - reported to the test
            outcome["error"] = exc
        finally:
            c.close()

    worker = threading.Thread(target=purge)
    worker.start()
    try:
        assert started.wait(30), "the purge never reached the store"
        # Both rows are locked, the one being deleted and the one not yet
        # reached: the batch was approved as a unit.
        for exhibit in ids:
            racer = s.owner_conn()
            try:
                racer.execute("SET lock_timeout = '500ms'")
                with pytest.raises(psycopg.errors.LockNotAvailable):
                    _service(racer).set_legal_hold(exhibit, actor_id=boss, on=True,
                                                   reason=REASON)
            finally:
                racer.close()
    finally:
        release.set()
        worker.join(60)
    assert "error" not in outcome, outcome.get("error")
    assert outcome["result"].evidence_purged == 2
    for exhibit in ids:
        assert g.evidence_row(conn, exhibit)[3], "not marked destroyed"
        with pytest.raises(RetentionError, match="destroyed"):
            _service(conn).set_legal_hold(exhibit, actor_id=boss, on=True, reason=REASON)
        assert not g.evidence_row(conn, exhibit)[4]
    applied = [r for r in g.audit_rows(conn, "LEGAL_HOLD_APPLIED", case_id=case_id)]
    assert applied == [], "a hold was acknowledged on an exhibit that was destroyed"


def test_a_case_hold_entered_during_the_sweep_waits_for_the_sweep(conn):
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    one, _ = g.lodge(conn, store, case_id, boss)
    two, _ = g.lodge(conn, store, case_id, boss)
    g.age_case(conn, case_id, g.expired())
    first = sorted([one.evidence_id, two.evidence_id])[0]
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
            outcome["result"] = _service(c, store).purge_due(
                actor_id=boss, authority=AUTHORITY, case_id=case_id)
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc
        finally:
            c.close()

    worker = threading.Thread(target=sweep)
    worker.start()
    try:
        assert started.wait(30), "the sweep never reached the store"
        racer = s.owner_conn()
        try:
            racer.execute("SET lock_timeout = '500ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                _service(racer).set_case_legal_hold(
                    case_id, actor_id=boss, on=True, reason=REASON,
                    lifter_ceiling=("RED", []))
        finally:
            racer.close()
    finally:
        release.set()
        worker.join(60)
    assert "error" not in outcome, outcome.get("error")
    assert outcome["result"].evidence_purged == 2
    # Placed afterwards, the case hold lands (it is preservation of whatever
    # the case still holds) and the destroyed exhibits stay destroyed.
    _service(conn).set_case_legal_hold(case_id, actor_id=boss, on=True,
                                       reason=REASON, lifter_ceiling=("RED", []))
    assert conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0] is True


def test_a_case_hold_entered_during_the_sweep_keeps_the_exhibits_it_has_not_reached(conn):
    """Beta 1 verification, group C, C6. The sweep took the case FOR SHARE
    once and kept it to the end, so a case hold entered during the first
    exhibit's delete waited out the WHOLE sweep and then landed on three
    destroyed exhibits with no word. Each exhibit is now claimed in a
    transaction of its own: the hold waits only for the exhibit in flight,
    and every exhibit after it is read as held and kept."""
    import time

    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    exhibits = [g.lodge(conn, store, case_id, boss, title=f"e{i}")[0].evidence_id
                for i in range(3)]
    g.age_case(conn, case_id, g.expired())
    first, *later = sorted(exhibits)
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
            outcome["result"] = _service(c, store).purge_due(
                actor_id=boss, authority=AUTHORITY, case_id=case_id)
        except Exception as exc:  # noqa: BLE001 - reported to the test
            outcome["error"] = exc
        finally:
            c.close()

    def hold():
        c = s.owner_conn()
        try:
            outcome["hold"] = _service(c).set_case_legal_hold(
                case_id, actor_id=boss, on=True, reason=REASON,
                lifter_ceiling=("RED", []))
        except Exception as exc:  # noqa: BLE001 - reported to the test
            outcome["hold_error"] = exc
        finally:
            c.close()

    sweeper = threading.Thread(target=sweep)
    holder = threading.Thread(target=hold)
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

    result = outcome["result"]
    assert result.evidence_purged == 1
    assert g.evidence_row(conn, first)[3], "the exhibit in flight was destroyed"
    for exhibit in later:
        assert not g.evidence_row(conn, exhibit)[3], (
            "an exhibit the case hold reached first was destroyed")
    assert store.deleted == [key_first]
    assert result.held_back == 2
    assert any("came under a legal hold" in w for w in result.warnings)
    assert conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0] is True
