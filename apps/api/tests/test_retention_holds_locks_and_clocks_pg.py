"""Retention: holds, the purge's locks, category clocks and samples (unit g44,
2026-10-03).

- evidence-purge-hold-race: a hold placed after the sweep keeps its exhibit,
  one placed while the store deletes waits for the purge and is then refused
  as the destroyed exhibit it is, and the database refuses the two states
  together. Proven with a second connection and a store that stops in the
  middle of a delete.
- evidence-purge-stalls-audit-chain: nothing audited is written, and so the
  chain's global lock is not taken, while the store deletes.
- evidence-case-hold-unreachable: a case-level hold can be placed and lifted,
  and binds exhibits (those lodged after it too), ingest records and samples.
- evidence-category-clock-outlives-case: a category clock only shortens.
- lab-4: an expired case's samples are disposed of by the purge, and a purged
  case's sample is not handed out.

Accounts `g44t-*`. No test writes to the real object store.
"""
from __future__ import annotations

import threading
from datetime import date, datetime, time, timedelta, timezone
from uuid import uuid4

import psycopg
import pytest

import g44_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

AUTHORITY = "g44 retention schedule 2026-10"
REASON = "preservation order 2026-17, g44 test"


def _service(conn, store=None, **kw):
    from noctornal_api.retention import RetentionService
    return RetentionService(conn, store, **kw)


def _expired_case_with_two_exhibits(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    one, _ = g.lodge(conn, store, case_id, boss, title="first")
    two, _ = g.lodge(conn, store, case_id, boss, title="second")
    g.age_case(conn, case_id, g.expired())
    return boss, case_id, one.evidence_id, two.evidence_id


def _purged(conn, evidence_id) -> bool:
    return g.evidence_row(conn, evidence_id)[3]


def _held(conn, evidence_id) -> bool:
    return g.evidence_row(conn, evidence_id)[4]


# --- evidence-purge-hold-race ---------------------------------------------

def test_a_hold_placed_after_the_sweep_keeps_its_exhibit(conn, monkeypatch):
    store = g.VersionedStore()
    boss, case_id, one, two = _expired_case_with_two_exhibits(conn, store)
    svc = _service(conn, store)
    swept = svc.due(case_id=case_id)
    assert {i.object_id for i in swept if i.object_type == "evidence"} == {one, two}
    assert not any(i.held for i in swept)

    _service(conn).set_legal_hold(two, actor_id=boss, on=True, reason=REASON)
    monkeypatch.setattr(svc, "due", lambda **_kw: swept)  # the stale sweep
    result = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)

    assert result.evidence_purged == 1
    assert _purged(conn, one) and not _purged(conn, two)
    assert _held(conn, two)
    assert store.deleted == [g.evidence_row(conn, one)[0]], (
        "the held exhibit's bytes were never asked of the store")
    assert any("came under a legal hold" in w for w in result.warnings)
    assert result.held_back >= 1
    stone = svc.tombstones(case_id)[0]
    assert stone["object_count"] == 1 and stone["storage_outcome"] == "DELETED"


def _sweep_with_a_stop_in_the_first_delete(conn, *, hold_on):
    """Run the scheduled sweep of two exhibits in a thread of its own, stop
    it inside the store's delete of the exhibit it reaches FIRST, and from a
    second connection try to place a hold on `hold_on` ("first" or
    "second"). Returns (the sweep's outcome, what the racer saw: "placed" or
    "waited", the exhibits in the order the sweep took them, the store)."""
    from noctornal_api.retention import RetentionService
    store = g.VersionedStore()
    boss, case_id, one, two = _expired_case_with_two_exhibits(conn, store)
    first, second = sorted([one, two])
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

    worker = threading.Thread(target=sweep)
    worker.start()
    seen = None
    try:
        assert started.wait(30), "the sweep never reached the store"
        racer = s.owner_conn()
        try:
            racer.execute("SET lock_timeout = '700ms'")
            try:
                RetentionService(racer).set_legal_hold(
                    first if hold_on == "first" else second, actor_id=boss,
                    on=True, reason=REASON)
                seen = "placed"
            except psycopg.errors.LockNotAvailable:
                seen = "waited"
        finally:
            racer.close()
    finally:
        release.set()
        worker.join(60)
    assert "error" not in outcome, outcome.get("error")
    return outcome["result"], seen, (first, second), store, boss, case_id


def test_a_hold_on_the_exhibit_being_destroyed_waits_and_is_then_refused(conn):
    """The hold waits for the sweep's row lock (a lock_timeout makes the wait
    visible), and once the sweep has committed it finds the exhibit
    destroyed and is refused, never acknowledged as applied to something
    that is gone."""
    from noctornal_api.retention import RetentionError
    result, seen, (first, second), _store, boss, case_id = (
        _sweep_with_a_stop_in_the_first_delete(conn, hold_on="first"))
    assert seen == "waited"
    assert result.evidence_purged == 2
    assert _purged(conn, first) and _purged(conn, second)
    with pytest.raises(RetentionError, match="destroyed"):
        _service(conn).set_legal_hold(first, actor_id=boss, on=True, reason=REASON)
    assert not _held(conn, first)
    assert not [r for r in g.audit_rows(conn, "LEGAL_HOLD_APPLIED", case_id=case_id)
                if r[0].get("evidence_id") == str(first)], (
        "a hold was acknowledged on an exhibit that was already destroyed")


def test_a_hold_entered_while_the_sweep_is_part_way_is_honoured_where_it_has_not_reached(conn):
    """The review's reproduction: while the store deletes the first exhibit,
    a court order for the second is entered from another connection. It
    lands at once, and the sweep, which rereads the holds under the lock it
    takes for each exhibit before that exhibit's delete, keeps the second."""
    result, seen, (first, second), store, _boss, case_id = (
        _sweep_with_a_stop_in_the_first_delete(conn, hold_on="second"))
    assert seen == "placed"
    assert result.evidence_purged == 1
    assert _purged(conn, first) and not _purged(conn, second)
    assert _held(conn, second)
    assert store.deleted == [g.evidence_row(conn, first)[0]], (
        "the store was asked to destroy the exhibit the hold had reached")
    assert any("came under a legal hold" in w for w in result.warnings)
    assert result.held_back >= 1
    stone = _service(conn).tombstones(case_id)[0]
    assert stone["object_count"] == 1 and stone["storage_outcome"] == "DELETED"


def test_a_case_hold_placed_after_the_sweep_keeps_everything(conn, monkeypatch):
    store = g.VersionedStore()
    boss, case_id, one, two = _expired_case_with_two_exhibits(conn, store)
    svc = _service(conn, store)
    swept = svc.due(case_id=case_id)
    _service(conn).set_case_legal_hold(
        case_id, actor_id=boss, on=True, reason=REASON,
        lifter_ceiling=("RED", []))
    monkeypatch.setattr(svc, "due", lambda **_kw: swept)
    result = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert result.evidence_purged == 0 and store.deleted == []
    assert not _purged(conn, one) and not _purged(conn, two)
    assert any("came under a legal hold" in w for w in result.warnings)


def test_the_database_refuses_a_held_exhibit_marked_destroyed(conn):
    store = g.VersionedStore()
    boss, case_id, one, two = _expired_case_with_two_exhibits(conn, store)
    _service(conn).set_legal_hold(one, actor_id=boss, on=True, reason=REASON)
    with pytest.raises(psycopg.errors.CheckViolation, match="legal hold"):
        with conn.transaction():
            conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s",
                         (one,))
    _service(conn).set_case_legal_hold(
        case_id, actor_id=boss, on=True, reason=REASON,
        lifter_ceiling=("RED", []))
    with pytest.raises(psycopg.errors.CheckViolation, match="legal hold"):
        with conn.transaction():
            conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s",
                         (two,))
    assert not _purged(conn, one) and not _purged(conn, two)


def test_the_database_refuses_a_hold_on_a_destroyed_exhibit(conn):
    store = g.VersionedStore()
    boss, case_id, one, _two = _expired_case_with_two_exhibits(conn, store)
    conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (one,))
    with pytest.raises(psycopg.errors.CheckViolation, match="destroyed"):
        with conn.transaction():
            conn.execute("UPDATE core.evidence SET legal_hold = true, "
                         "legal_hold_reason = 'x' WHERE id = %s", (one,))


# --- evidence-purge-stalls-audit-chain ------------------------------------

def _approved_early_purge(conn, case_id, boss, exhibits):
    from noctornal_api.approvals import ApprovalService
    approver = g.user(conn, "RED")
    payload = {"case_id": str(case_id),
               "evidence_ids": sorted(str(e) for e in exhibits),
               "authority": AUTHORITY}
    req = ApprovalService(conn).request(
        operation="evidence.purge", case_id=case_id, payload=payload,
        justification="g44 early destruction", requested_by=boss)
    ApprovalService(conn).decide(req.id, decided_by=approver, approve=True)
    return req.id


def test_the_audit_chain_is_not_held_while_the_store_deletes(conn):
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)                     # retention 2030: not due
    one, _ = g.lodge(conn, store, case_id, boss)
    two, _ = g.lodge(conn, store, case_id, boss)
    request_id = _approved_early_purge(conn, case_id, boss,
                                       [one.evidence_id, two.evidence_id])
    started, release = threading.Event(), threading.Event()
    waited: dict = {}
    outcome: dict = {}

    def stop_in_the_delete(_key):
        if not started.is_set():
            started.set()
            assert release.wait(30)

    store.on_delete = stop_in_the_delete

    def purge():
        c = s.owner_conn()
        try:
            outcome["result"] = _service(c, store).purge_out_of_schedule(
                actor_id=boss, authority=AUTHORITY, approval_request_id=request_id,
                case_id=case_id, evidence_ids=[one.evidence_id, two.evidence_id])
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc
        finally:
            c.close()

    worker = threading.Thread(target=purge)
    worker.start()
    try:
        assert started.wait(30), "the purge never reached the store"
        other = s.owner_conn()
        try:
            other.execute("SET lock_timeout = '1500ms'")
            began = datetime.now(timezone.utc)
            # An unrelated audited write, as every login and view is one.
            other.execute(
                "INSERT INTO audit.event (actor_kind, action, outcome) "
                "VALUES ('SYSTEM', 'G44_CHAIN_PROBE', 'SUCCESS')")
            waited["seconds"] = (datetime.now(timezone.utc) - began).total_seconds()
        finally:
            other.close()
    finally:
        release.set()
        worker.join(60)
    assert "error" not in outcome, outcome.get("error")
    assert waited["seconds"] < 1.5
    assert outcome["result"].evidence_purged == 2
    assert _purged(conn, one.evidence_id) and _purged(conn, two.evidence_id)
    from noctornal_api.approvals import ApprovalService
    assert ApprovalService(conn).get(request_id).state == "CONSUMED"


def test_a_hold_that_arrives_before_the_locks_refuses_the_whole_early_purge(conn):
    """The check before the approval, and the reread under the locks: a hold
    that lands between them refuses the purge, destroys nothing and leaves
    the approval usable."""
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.retention import RetentionError
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    one, _ = g.lodge(conn, store, case_id, boss)
    request_id = _approved_early_purge(conn, case_id, boss, [one.evidence_id])
    svc = _service(conn, store)
    # The hold lands after the unlocked check and before the locks: stand in
    # for the check by letting the first read say "not held".
    original = svc._c.execute
    state = {"armed": True}

    class Spy:
        def __getattr__(self, name):
            return getattr(conn, name)

        def execute(self, sql, params=None, **kw):
            if (state["armed"] and "FROM core.evidence e" in str(sql)
                    and "legal_hold OR c.legal_hold" in str(sql)
                    and "count(*)" in str(sql)):
                state["armed"] = False
                cur = original(sql, params, **kw)
                _service(conn).set_legal_hold(one.evidence_id, actor_id=boss,
                                              on=True, reason=REASON)
                return cur
            return original(sql, params, **kw)

    spy_svc = _service(Spy(), store)
    with pytest.raises(RetentionError, match="legal hold"):
        spy_svc.purge_out_of_schedule(
            actor_id=boss, authority=AUTHORITY, approval_request_id=request_id,
            case_id=case_id, evidence_ids=[one.evidence_id])
    assert not _purged(conn, one.evidence_id) and store.deleted == []
    assert ApprovalService(conn).get(request_id).state == "APPROVED"


def test_an_early_purge_names_at_most_a_bounded_number_of_exhibits(conn):
    from noctornal_api.retention import MAX_OUT_OF_SCHEDULE, RetentionError
    ids = [uuid4() for _ in range(MAX_OUT_OF_SCHEDULE + 1)]
    with pytest.raises(RetentionError, match="at most"):
        _service(conn, g.VersionedStore()).purge_out_of_schedule(
            actor_id=uuid4(), authority=AUTHORITY, approval_request_id=uuid4(),
            case_id=uuid4(), evidence_ids=ids)


# --- evidence-case-hold-unreachable ---------------------------------------

def _sample_service(conn, memory):
    from noctornal_api.samples import SampleService
    return SampleService(conn, memory)


class MemorySamples:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


@pytest.fixture
def lab(monkeypatch):
    from noctornal_api.samples import DISPOSITION_ENV
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")
    monkeypatch.setenv(DISPOSITION_ENV, "destroy")
    return MemorySamples()


def _active(conn, case_id, boss):
    from noctornal_api.cases import CaseService
    CaseService(conn).transition_status(case_id, "ACTIVE", actor_id=boss)


def _sample(conn, memory, case_id, submitter, **kw):
    return _sample_service(conn, memory).submit(
        b"MZ-g44-not-malware-" + uuid4().bytes, submitted_by=submitter,
        original_filename="x.bin", case_id=case_id, **kw)


def test_a_case_hold_freezes_everything_the_case_governs(conn, lab):
    """An exhibit lodged before the order, one lodged after it, an ingest
    record and a sample: all four are held by the case, none is destroyed,
    and lifting the hold lets the sweep take them."""
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    _active(conn, case_id, boss)
    before, _ = g.lodge(conn, store, case_id, boss, title="before the order")
    record_id, _ = g.record_in_case(conn, boss, case_id)
    sample = _sample(conn, lab, case_id, boss)

    out = _service(conn).set_case_legal_hold(
        case_id, actor_id=boss, on=True, reason=REASON, lifter_ceiling=("RED", []))
    assert out["legal_hold"] is True
    after, _ = g.lodge(conn, store, case_id, boss, title="after the order")
    g.age_case(conn, case_id, g.expired())

    svc = _service(conn, store, sample_stores=lambda: (lab, None))
    items = svc.due(case_id=case_id)
    kinds = {(i.object_type, i.object_id): i for i in items}
    for key in (("evidence", before.evidence_id), ("evidence", after.evidence_id),
                ("ingest_record", record_id), ("sample", sample.id)):
        assert key in kinds, key
        assert kinds[key].held and kinds[key].hold_reason == "case-level legal hold"
    result = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert (result.evidence_purged, result.records_purged,
            result.samples_purged) == (0, 0, 0)
    assert result.held_back >= 4 and store.deleted == []
    assert not _purged(conn, before.evidence_id) and not _purged(conn, after.evidence_id)
    assert conn.execute("SELECT purged_at FROM ingest.record WHERE id = %s",
                        (record_id,)).fetchone()[0] is None
    assert conn.execute("SELECT state FROM lab.sample WHERE id = %s",
                        (sample.id,)).fetchone()[0] != "REJECTED"
    assert g.audit_rows(conn, "LEGAL_HOLD_APPLIED", case_id=case_id)[0][0]["scope"] == "case"

    _service(conn).set_case_legal_hold(
        case_id, actor_id=boss, on=False, reason="order lifted, g44 test",
        lifter_ceiling=("RED", ["STEALER-2026"]))
    freed = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert (freed.evidence_purged, freed.records_purged, freed.samples_purged) == (2, 1, 1)


def test_a_case_hold_needs_a_reason_both_ways_and_says_what_it_replaced(conn):
    from noctornal_api.retention import RetentionError, RetentionNotFound
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    svc = _service(conn)
    for bad in (None, "", "  ", "no"):
        with pytest.raises(RetentionError, match="say what it rests on"):
            svc.set_case_legal_hold(case_id, actor_id=boss, on=True, reason=bad,
                                    lifter_ceiling=("RED", []))
    svc.set_case_legal_hold(case_id, actor_id=boss, on=True, reason=REASON)
    with pytest.raises(RetentionError, match="say what it rests on"):
        svc.set_case_legal_hold(case_id, actor_id=boss, on=False, reason=None,
                                lifter_ceiling=("RED", []))
    svc.set_case_legal_hold(case_id, actor_id=boss, on=False, reason="released by order",
                            lifter_ceiling=("RED", []))
    lifted = g.audit_rows(conn, "LEGAL_HOLD_LIFTED", case_id=case_id)[0][0]
    assert lifted["prior_on"] is True and lifted["prior_reason"] == REASON
    with pytest.raises(RetentionNotFound):
        svc.set_case_legal_hold(uuid4(), actor_id=boss, on=True, reason=REASON)


def test_a_case_hold_is_lifted_only_by_somebody_cleared_for_all_of_it(conn):
    """The case-level twin of evidence-hold-lift-below-label: a lead below an
    exhibit may place the hold, and may not release it."""
    from noctornal_api.retention import RetentionError
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    red, _ = g.lodge(conn, store, case_id, boss, classification="RED")
    svc = _service(conn)
    svc.set_case_legal_hold(case_id, actor_id=boss, on=True, reason=REASON)
    for ceiling in (("AMBER", []), None):
        with pytest.raises(RetentionError, match="cleared for everything"):
            svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                    reason="released by order", lifter_ceiling=ceiling)
    assert conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0] is True
    # Each refusal is recorded (2026-10-07: it left no row at all), and
    # the row names nothing above the lifter.
    refused = conn.execute(
        """SELECT outcome, detail FROM audit.event
            WHERE action = 'LEGAL_HOLD_LIFT_REFUSED' AND case_id = %s
            ORDER BY seq""", (case_id,)).fetchall()
    assert [r[0] for r in refused] == ["DENIED", "DENIED"]
    assert set(refused[0][1]) == {"case_id", "scope", "reason"}
    out = svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                  reason="released by order",
                                  lifter_ceiling=("RED", []))
    assert out["legal_hold"] is False
    assert not _purged(conn, red.evidence_id)


def test_a_compartmented_exhibit_also_keeps_the_case_hold_from_a_lead_not_read_in(conn):
    from noctornal_api.retention import RetentionError
    store = g.VersionedStore()
    boss = g.user(conn, "RED", compartments=("G44-HELD",))
    case_id = g.case(conn, boss)
    g.lodge(conn, store, case_id, boss, classification="AMBER",
            compartments=["G44-HELD"])
    svc = _service(conn)
    svc.set_case_legal_hold(case_id, actor_id=boss, on=True, reason=REASON)
    with pytest.raises(RetentionError):
        svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                reason="released by order",
                                lifter_ceiling=("RED", []))
    svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                            reason="released by order",
                            lifter_ceiling=("RED", ["G44-HELD"]))


def test_a_lift_with_an_unknown_clearance_refuses(conn):
    from noctornal_api.retention import RetentionError
    from noctornal_api.security.access import AccessResolutionError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    svc = _service(conn)
    svc.set_case_legal_hold(case_id, actor_id=boss, on=True, reason=REASON)
    with pytest.raises((RetentionError, AccessResolutionError)):
        svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                reason="released by order",
                                lifter_ceiling=("NOT-A-LABEL", []))
    assert conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0] is True


# --- case-hold-lift-documents -------------------------------------------
#
# The case-hold lift gate counted exhibits, records, samples and lookups above
# the lifter and not the collected documents the case cites, which are held
# only through the case: a lead cleared below a RED document lifted the case
# hold alone and the document sweep could then destroy it.

def _document_hold(conn, doc):
    """The hold reason of a collected document, from the predicate the sweep
    and the due list both read."""
    from noctornal_api.retention import _held_sql
    return conn.execute(f"SELECT {_held_sql('d')} FROM collect.document d "
                        "WHERE d.id = %s", (doc,)).fetchone()[0]


CASE_HOLD_ON_DOCUMENT = "cited by a case under legal hold"


def _held_case_citing(conn, *, classification="RED", compartments=(), **kw):
    """An AMBER case under a case hold that cites one collected document at
    the given labels. Returns (boss, case id, document id)."""
    boss = g.user(conn, "RED", compartments=compartments)
    case_id = g.case(conn, boss)
    doc, _source = g.collected_document(
        conn, case_id, classification=classification,
        compartments=compartments, **kw)
    _service(conn).set_case_legal_hold(case_id, actor_id=boss, on=True, reason=REASON)
    return boss, case_id, doc


def test_a_cited_red_document_keeps_the_case_hold_from_a_lead_below_it(conn):
    from noctornal_api.retention import RetentionError
    boss, case_id, doc = _held_case_citing(conn)
    assert _document_hold(conn, doc) == CASE_HOLD_ON_DOCUMENT
    svc = _service(conn)
    for ceiling in (("AMBER", []), ("GREEN", []), None):
        with pytest.raises(RetentionError, match="cleared for everything"):
            svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                    reason="released by the lead",
                                    lifter_ceiling=ceiling)
    assert _case_is_held(conn, case_id)
    assert _document_hold(conn, doc) == CASE_HOLD_ON_DOCUMENT
    out = svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                  reason="order discharged by the court",
                                  lifter_ceiling=("RED", []))
    assert out["legal_hold"] is False
    assert _document_hold(conn, doc) is None


def _case_is_held(conn, case_id) -> bool:
    return conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]


def test_a_compartmented_document_keeps_the_case_hold_from_a_lead_not_read_in(conn):
    from noctornal_api.retention import RetentionError
    boss, case_id, doc = _held_case_citing(
        conn, classification="AMBER", compartments=("G44-DOC",))
    svc = _service(conn)
    with pytest.raises(RetentionError, match="cleared for everything"):
        svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                reason="released by the lead",
                                lifter_ceiling=("RED", []))
    assert _document_hold(conn, doc) == CASE_HOLD_ON_DOCUMENT
    svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                            reason="order discharged by the court",
                            lifter_ceiling=("RED", ["G44-DOC"]))
    assert _document_hold(conn, doc) is None


def test_a_red_version_of_a_cited_post_counts_though_only_another_version_is_cited(conn):
    """A citation of any version holds every version, so the lift gate
    counts every version too."""
    from noctornal_api.retention import RetentionError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    first, source = g.collected_document(
        conn, case_id, classification="AMBER", external_id="post:g44-1")
    second, _ = g.collected_document(
        conn, case_id, classification="RED", source=source,
        external_id="post:g44-1", version=2, supersedes=first, cited=False)
    svc = _service(conn)
    svc.set_case_legal_hold(case_id, actor_id=boss, on=True, reason=REASON)
    assert _document_hold(conn, second) == CASE_HOLD_ON_DOCUMENT
    with pytest.raises(RetentionError, match="cleared for everything"):
        svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                reason="released by the lead",
                                lifter_ceiling=("AMBER", []))
    assert _case_is_held(conn, case_id)


def test_what_the_case_does_not_cite_or_the_sweep_already_destroyed_does_not_count(conn):
    """A RED document cited by another case, an uncited one and a purged one
    are not this case's to be cleared for."""
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    other = g.case(conn, boss)
    g.collected_document(conn, other, classification="RED")
    g.collected_document(conn, case_id, classification="RED", cited=False)
    g.collected_document(conn, case_id, classification="RED", purged=True)
    mine, _ = g.collected_document(conn, case_id, classification="AMBER")
    svc = _service(conn)
    svc.set_case_legal_hold(case_id, actor_id=boss, on=True, reason=REASON)
    assert _document_hold(conn, mine) == CASE_HOLD_ON_DOCUMENT
    out = svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                  reason="order discharged by the court",
                                  lifter_ceiling=("AMBER", []))
    assert out["legal_hold"] is False


def test_a_grant_scoped_to_the_case_does_not_release_a_document_it_cannot_open(conn):
    """The case ceiling includes a case-scoped break-glass grant and a
    document is read under the account's own clearance, so the document leg
    takes the lower of the two."""
    from noctornal_api.retention import RetentionError
    boss, case_id, doc = _held_case_citing(conn)
    svc = _service(conn)
    with pytest.raises(RetentionError, match="cleared for everything"):
        svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                                reason="released on a case-scoped grant",
                                lifter_ceiling=("RED", []),
                                document_ceiling=("AMBER", []))
    assert _document_hold(conn, doc) == CASE_HOLD_ON_DOCUMENT
    svc.set_case_legal_hold(case_id, actor_id=boss, on=False,
                            reason="order discharged by the court",
                            lifter_ceiling=("RED", []),
                            document_ceiling=("RED", []))
    assert _document_hold(conn, doc) is None


# --- evidence-category-clock-outlives-case --------------------------------

def _rule_days(conn, category="STEALER_LOG") -> int:
    row = conn.execute("SELECT retain_days FROM core.retention_rule "
                       "WHERE category = %s", (category,)).fetchone()
    from noctornal_api.retention import UNRULED_RETAIN_DAYS
    return row[0] if row else UNRULED_RETAIN_DAYS


def _midnight(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=timezone.utc)


def test_a_record_never_outlives_the_case_it_arrives_in(conn):
    boss = g.user(conn, "RED")
    days = _rule_days(conn)
    retention = date.today() + timedelta(days=max(2, days // 3))
    case_id = g.case(conn, boss, retention=retention)
    record_id, retain_until = g.record_in_case(conn, boss, case_id)
    assert retain_until == _midnight(retention), (
        f"the category clock ({days} days) outlived the case ({retention})")
    items = [i for i in _service(conn).due(case_id=case_id,
                                           as_of=_midnight(retention) + timedelta(hours=1))
             if i.object_type == "ingest_record"]
    assert [i.object_id for i in items] == [record_id]


def test_a_category_clock_that_is_shorter_is_kept(conn):
    boss = g.user(conn, "RED")
    days = _rule_days(conn)
    retention = date.today() + timedelta(days=days * 10)
    case_id = g.case(conn, boss, retention=retention)
    _record_id, retain_until = g.record_in_case(conn, boss, case_id)
    expected = datetime.now(timezone.utc) + timedelta(days=days)
    assert abs((retain_until - expected).total_seconds()) < 300
    assert retain_until < _midnight(retention)


def test_the_sweep_takes_the_earlier_of_the_stamp_and_the_case(conn):
    """A record stamped before this change, or attached later, is covered by
    the sweep's own LEAST."""
    boss = g.user(conn, "RED")
    retention = date.today() + timedelta(days=15)
    case_id = g.case(conn, boss, retention=retention)
    record_id, _ = g.record_in_case(conn, boss, case_id)
    conn.execute("UPDATE ingest.record SET retain_until = now() + interval '700 days' "
                 "WHERE id = %s", (record_id,))
    svc = _service(conn)
    assert [i for i in svc.due(case_id=case_id) if i.object_type == "ingest_record"] == []
    soon = _midnight(retention) + timedelta(hours=1)
    [item] = [i for i in svc.due(case_id=case_id, as_of=soon)
              if i.object_type == "ingest_record"]
    assert item.object_id == record_id and item.rule == "case.retention_until"
    assert item.deadline == _midnight(retention)


# --- lab-4 -----------------------------------------------------------------

def test_an_expired_cases_sample_is_disposed_of_by_the_purge(conn, lab):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    _active(conn, case_id, boss)
    sample = _sample(conn, lab, case_id, boss)
    key = conn.execute("SELECT storage_key FROM lab.sample WHERE id = %s",
                       (sample.id,)).fetchone()[0]
    assert key in lab.objects
    g.age_case(conn, case_id, g.expired())

    svc = _service(conn, g.VersionedStore(), sample_stores=lambda: (lab, None))
    assert [(i.object_type, i.object_id) for i in svc.due(case_id=case_id)] == [
        ("sample", sample.id)]
    dry = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id,
                        dry_run=True)
    assert dry.samples_purged == 1 and key in lab.objects

    result = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)

    assert result.samples_purged == 1
    assert key not in lab.objects, "the sample's bytes outlived its case"
    state, data_key = conn.execute(
        "SELECT state, data_key_ciphertext FROM lab.sample WHERE id = %s",
        (sample.id,)).fetchone()
    assert state == "REJECTED" and bytes(data_key) == b""
    stones = [t for t in svc.tombstones(case_id) if t["object_type"] == "sample"]
    assert len(stones) == 1 and stones[0]["object_count"] == 1
    assert stones[0]["storage_outcome"] == "DELETED"
    assert svc.due(case_id=case_id) == [], "a disposed sample is not due again"


def test_a_samples_own_hold_keeps_it_through_the_purge(conn, lab):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    _active(conn, case_id, boss)
    sample = _sample(conn, lab, case_id, boss)
    conn.execute("UPDATE lab.sample SET legal_hold = true WHERE id = %s", (sample.id,))
    g.age_case(conn, case_id, g.expired())
    svc = _service(conn, g.VersionedStore(), sample_stores=lambda: (lab, None))
    [item] = svc.due(case_id=case_id)
    assert item.held and item.hold_reason == "sample-level legal hold"
    result = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert result.samples_purged == 0 and result.held_back == 1
    assert conn.execute("SELECT state FROM lab.sample WHERE id = %s",
                        (sample.id,)).fetchone()[0] != "REJECTED"


def test_with_no_sample_store_the_sample_stays_due_and_the_purge_says_so(conn, lab):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    _active(conn, case_id, boss)
    sample = _sample(conn, lab, case_id, boss)
    g.age_case(conn, case_id, g.expired())
    svc = _service(conn, g.VersionedStore())
    result = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert result.samples_purged == 0
    assert any("not disposed of" in w for w in result.warnings)
    assert [i.object_id for i in svc.due(case_id=case_id)] == [sample.id]


def test_a_purged_cases_sample_is_not_handed_out(conn, lab):
    from noctornal_api.samples import SampleError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    _active(conn, case_id, boss)
    sample = _sample(conn, lab, case_id, boss)
    svc = _sample_service(conn, lab)
    assert svc._downloadable(sample.id, clearance="RED")[0]
    from noctornal_api.cases import CaseService
    for state in ("CLOSED", "ARCHIVED", "PURGED"):
        CaseService(conn).transition_status(case_id, state, actor_id=boss)
    with pytest.raises(SampleError, match="purged"):
        svc._downloadable(sample.id, clearance="RED")


# --- 2026-10-07 ------------------------------
#
# C4: a case hold committed while a destroying rejection deletes the sample's
#     bytes was missed, because the hold was reread with a plain read.
# C5: the store's delete and the exhibit's `purged_at` shared one
#     transaction with everything after them, so a failure after a delete
#     left the object destroyed and the row unmarked.
# C6: a case hold entered mid-purge landed after the whole sweep had run.
#     (`test_g44_races_pg.py` holds the two-connection test.)
# C8: a sweep that names no case never reread the case hold of a record.

def test_a_case_hold_entered_while_a_sample_is_destroyed_waits_for_it(conn, lab):
    """`SampleService._reject_destroying` reread the hold under the sample's
    row lock only, and `set_case_legal_hold` writes the case row, so a case
    hold committed during the store's delete went unseen: the sample was
    REJECTED, its bytes gone and the case held. The case row is now held
    FOR SHARE before the reread, so the hold waits for the rejection."""
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    _active(conn, case_id, boss)
    sample = _sample(conn, lab, case_id, boss)
    seen: dict = {}
    real_delete = lab.delete

    def delete_with_a_hold_entered_meanwhile(key):
        racer = s.owner_conn()
        try:
            racer.execute("SET lock_timeout = '700ms'")
            try:
                _service(racer).set_case_legal_hold(
                    case_id, actor_id=boss, on=True, reason=REASON,
                    lifter_ceiling=("RED", []))
                seen["hold"] = "placed"
            except psycopg.errors.LockNotAvailable:
                seen["hold"] = "waited"
        finally:
            racer.close()
        real_delete(key)

    lab.delete = delete_with_a_hold_entered_meanwhile
    _sample_service(conn, lab).reject(
        sample.id, actor_id=boss, reason="prohibited content, policy POL-2026-014")

    assert seen["hold"] == "waited", (
        "a case hold was committed while the sample's bytes were destroyed")
    assert conn.execute("SELECT state FROM lab.sample WHERE id = %s",
                        (sample.id,)).fetchone()[0] == "REJECTED"


def test_a_case_hold_already_written_still_refuses_to_destroy_a_sample(conn, lab):
    from noctornal_api.samples import SampleError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    _active(conn, case_id, boss)
    sample = _sample(conn, lab, case_id, boss)
    _service(conn).set_case_legal_hold(case_id, actor_id=boss, on=True,
                                       reason=REASON, lifter_ceiling=("RED", []))
    with pytest.raises(SampleError, match="legal hold"):
        _sample_service(conn, lab).reject(
            sample.id, actor_id=boss, reason="prohibited content, policy POL-2026-014")
    assert lab.objects, "the bytes were destroyed under a hold"


class _Crash(BaseException):
    """What a dropped connection or a killed worker looks like to the code
    above it: not an `Exception` the purge counts, a failure it cannot
    catch."""


def test_a_failure_part_way_leaves_the_destroyed_exhibits_marked(conn):
    """Each exhibit is marked destroyed in the transaction that destroyed it
    (Beta 1, C5). The object store's delete cannot be rolled back, so a
    purge that fails on the second of three exhibits must not take the
    first one's mark with it: before, the first object was gone, its row
    read live, and every later read raised an integrity alarm for it."""
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    ids = sorted(g.lodge(conn, store, case_id, boss, title=f"e{i}")[0].evidence_id
                 for i in range(3))
    g.age_case(conn, case_id, g.expired())
    keys = {i: g.evidence_row(conn, i)[0] for i in ids}

    def crash_on_the_second(key):
        if key == keys[ids[1]]:
            raise _Crash()

    store.on_delete = crash_on_the_second
    with pytest.raises(_Crash):
        _service(conn, store).purge_due(actor_id=boss, authority=AUTHORITY,
                                        case_id=case_id)
    assert _purged(conn, ids[0]), (
        "an exhibit whose object the store had deleted was left unmarked")
    assert not _purged(conn, ids[1]) and not _purged(conn, ids[2])
    assert store.deleted == [keys[ids[0]]]
    # What is left is due again, and the destroyed one is not.
    due = {i.object_id for i in _service(conn, store).due(case_id=case_id)}
    assert due == {ids[1], ids[2]}


def test_a_tombstone_that_fails_does_not_undo_the_marks_and_says_what_happened(conn):
    """The failure the verifier simulated: everything after the store's
    delete failed. The marks stand (the objects are gone), and the error
    names what was destroyed without a tombstone, so nobody reads a retry
    as a way to record it."""
    from noctornal_api.retention import RetentionError
    store = g.VersionedStore()
    boss, case_id, one, two = _expired_case_with_two_exhibits(conn, store)
    svc = _service(conn, store)

    def boom(*_a, **_k):
        raise RuntimeError("the audit chain lock timed out")

    svc._tombstone = boom
    with pytest.raises(RetentionError, match="tombstone") as caught:
        svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert "2 exhibits" in str(caught.value)
    assert _purged(conn, one) and _purged(conn, two)
    assert conn.execute(
        "SELECT count(*) FROM core.purge_tombstone WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 0


def test_a_later_leg_that_fails_does_not_undo_the_exhibits(conn):
    """The exhibit leg no longer shares a transaction with the documents,
    records and lookups after it."""
    store = g.VersionedStore()
    boss, case_id, one, two = _expired_case_with_two_exhibits(conn, store)
    svc = _service(conn, store)

    def boom(*_a, **_k):
        raise RuntimeError("a later leg failed")

    svc._purge_lookups = boom
    with pytest.raises(RuntimeError, match="later leg"):
        svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert _purged(conn, one) and _purged(conn, two)
    assert len(svc.tombstones(case_id)) == 1


def test_a_case_hold_placed_after_a_caseless_sweep_keeps_a_record(conn, monkeypatch):
    """`purge_due(case_id=None)` never reread the case hold (Beta 1, C8): a
    record the sweep had listed was emptied although a case hold had
    committed since. Only `retention_sweep.py` calls it without a case, and
    it restricts itself to documents, so this was latent."""
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    record_id, _ = g.record_in_case(conn, boss, case_id)
    g.age_case(conn, case_id, g.expired())
    svc = _service(conn, g.VersionedStore())
    swept = [i for i in svc.due() if i.object_id == record_id]
    assert [i.held for i in swept] == [False]

    _service(conn).set_case_legal_hold(case_id, actor_id=boss, on=True,
                                       reason=REASON, lifter_ceiling=("RED", []))
    monkeypatch.setattr(svc, "due", lambda **_kw: swept)  # the stale sweep
    result = svc.purge_due(actor_id=boss, authority=AUTHORITY,
                           kinds=frozenset({"ingest_record"}))

    assert result.records_purged == 0
    assert conn.execute("SELECT purged_at FROM ingest.record WHERE id = %s",
                        (record_id,)).fetchone()[0] is None
    assert result.held_back >= 1
    assert any("legal hold" in w for w in result.warnings)
