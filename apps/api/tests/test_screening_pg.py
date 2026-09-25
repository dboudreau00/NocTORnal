"""Prohibited-content screening against the database (F13, 2026-09-24).

What these hold, and what each would catch:

- a submission is screened BEFORE the duplicate check and any write: with
  no list nothing is compared and no result is written; a listed file is
  never QUARANTINED, is recorded REJECTED and MATCH, and its bytes are
  preserved (or, under destroy, never stored), with a 451-shaped refusal
  that names no list;
- a held sample of any state that matches is isolated in the request and
  its bytes moved by the worker; a closed case and a legal hold do not stop
  it; a match is permanent; a newer list rescreens; a failure stays
  pending and completes on a later pass; an absent object is recorded
  after two looks and the data key is never touched;
- waiting detonations are refused and a sent one is named, in a savepoint
  whose failure never undoes the isolation; a queued static run is never
  claimed for a match;
- the alerts are URGENT, GREEN, caseless and content-free, coalesced per
  recipient per hour, and their failure never undoes the isolation;
- a matched sample is hidden from every Lab reader and refused by every
  Lab write; its preservation authorisations are void on every door;
- lists: both authorities, one transaction, distinct entries, one active
  copy, retirement deletes nothing, the purge runs in batches and may be
  asked for later, and the records are append-only.

Email prefix `scr-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
import os
from datetime import timedelta
from uuid import uuid4

import pytest

from lab_static_fixtures import MemoryStore, make_case, make_user
from screening_fixtures import (
    MemoryPreservation,
    assert_scrubbed,
    declare,
    import_list,
    listed,
    notices,
    payload,
    scrub,
    service,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "scr-"


@pytest.fixture(autouse=True)
def authorities(monkeypatch):
    declare(monkeypatch)
    monkeypatch.delenv("NOCTORNAL_REJECTED_SAMPLE_DISPOSITION", raising=False)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def held():
    return MemoryPreservation()


@pytest.fixture
def officer(conn):
    return make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))


def _analyst(conn, **kw):
    return make_user(conn, PREFIX, roles=("ANALYST",), **kw)


def _row(conn, sample_id):
    return conn.execute(
        """SELECT state::text, screening_outcome, preserved_key,
                  octet_length(data_key_ciphertext), screening_bytes_absent_at,
                  screening_list_seq, reject_reason
             FROM lab.sample WHERE id = %s""", (sample_id,)).fetchone()


def _results(conn, sample_id):
    return conn.execute(
        """SELECT trigger, outcome, disposition, alert_outcome, detail,
                  officers_notified, actor_id
             FROM lab.screening_result WHERE sample_id = %s
            ORDER BY screened_at""", (sample_id,)).fetchall()


def _custody(conn, sample_id):
    return conn.execute(
        """SELECT action, actor_kind, detail FROM lab.sample_access
            WHERE sample_id = %s ORDER BY occurred_at, id""",
        (sample_id,)).fetchall()


def _sample_id_by_sha(conn, blob):
    row = conn.execute("SELECT id FROM lab.sample WHERE sha256 = %s",
                       (hashlib.sha256(blob).digest(),)).fetchone()
    return row[0] if row else None


# --- submission --------------------------------------------------------------

def test_with_no_list_a_submission_is_not_screened_and_writes_no_result(conn, store):
    who = _analyst(conn)
    s = service(conn, store).submit(payload("none"), submitted_by=who)
    assert s.screening_outcome == "NOT_SCREENED" and s.screened_at is None
    assert _results(conn, s.id) == []
    assert s.state == "QUARANTINED"


def test_a_clean_submission_under_an_active_list_is_no_match_with_one_result(conn, store, officer):
    who = _analyst(conn)
    import_list(conn, officer, listed(payload("other")))
    s = service(conn, store).submit(payload("clean"), submitted_by=who)
    assert s.screening_outcome == "NO_MATCH" and s.screened_at is not None
    rows = _results(conn, s.id)
    assert [(r[0], r[1]) for r in rows] == [("SUBMISSION", "NO_MATCH")]


def test_a_listed_sha256_is_isolated_at_submission_and_preserved(conn, store, held, officer):
    from noctornal_api.samples import ProhibitedContentMatch
    who = _analyst(conn)
    blob = payload("listed")
    import_list(conn, officer, listed(blob))
    svc = service(conn, store, held)
    with pytest.raises(ProhibitedContentMatch) as err:
        svc.submit(blob, submitted_by=who)
    message = str(err.value)
    assert "list" in message and "Do not open, copy or share" in message
    assert "OTHER_PROHIBITED" not in message and "Test provider" not in message
    sample_id = _sample_id_by_sha(conn, blob)
    state, outcome, preserved_key, key_len, absent, _seq, reason = _row(conn, sample_id)
    assert (state, outcome) == ("REJECTED", "MATCH")
    assert preserved_key and key_len > 0 and absent is None
    assert "prohibited-content" in reason
    # The working copy went in and came out; the held copy is the only one.
    assert store.objects == {}
    assert list(held.objects) == [preserved_key]
    custody = _custody(conn, sample_id)
    assert custody[0][:2] == ("VIEWED_META", "USER")
    assert custody[1][:2] == ("REJECTED", "SYSTEM")
    assert custody[1][2]["disposition"] == "preserve"
    assert custody[2][2]["event"] == "preserved_after_screening"
    (trigger, out, disposition, alert, _d, notified, actor), = _results(conn, sample_id)
    assert (trigger, out, disposition) == ("SUBMISSION", "MATCH", "PRESERVE")
    assert alert == "SENT" and notified >= 1 and actor == who
    # No static triage for a match.
    assert conn.execute("SELECT count(*) FROM lab.static_run WHERE sample_id = %s",
                        (sample_id,)).fetchone()[0] == 0
    # The match audit row is written as a refusal by the submitter.
    audit = conn.execute(
        """SELECT actor_id, outcome FROM audit.event
            WHERE action = 'SAMPLE_SCREENING_MATCH' AND object_id = %s""",
        (sample_id,)).fetchall()
    assert audit == [(who, "DENIED")]


def test_under_destroy_a_matched_submission_is_never_stored(conn, store, held, officer, monkeypatch):
    from noctornal_api.samples import ProhibitedContentMatch
    monkeypatch.setenv("NOCTORNAL_REJECTED_SAMPLE_DISPOSITION", "destroy")
    who = _analyst(conn)
    blob = payload("destroy")
    import_list(conn, officer, listed(blob))
    with pytest.raises(ProhibitedContentMatch):
        service(conn, store, held).submit(blob, submitted_by=who)
    sample_id = _sample_id_by_sha(conn, blob)
    _state, outcome, preserved_key, key_len, *_ = _row(conn, sample_id)
    assert outcome == "MATCH" and preserved_key is None and key_len == 0
    assert store.objects == {} and held.objects == {}
    assert _results(conn, sample_id)[0][2] == "NOT_STORED"


def test_a_case_hold_preserves_even_under_destroy(conn, store, held, officer, monkeypatch):
    from noctornal_api.samples import ProhibitedContentMatch
    monkeypatch.setenv("NOCTORNAL_REJECTED_SAMPLE_DISPOSITION", "destroy")
    who = _analyst(conn)
    case = make_case(conn, who)
    conn.execute('UPDATE core."case" SET legal_hold = true, '
                 "legal_hold_reason = 'preservation order' WHERE id = %s", (case,))
    blob = payload("hold")
    import_list(conn, officer, listed(blob))
    with pytest.raises(ProhibitedContentMatch):
        service(conn, store, held).submit(blob, submitted_by=who, case_id=case)
    sample_id = _sample_id_by_sha(conn, blob)
    assert _row(conn, sample_id)[2] is not None
    result = _results(conn, sample_id)[0]
    assert result[2] == "PRESERVE"
    assert result[4]["disposition_reasons"] == ["case_legal_hold"]


@pytest.mark.parametrize("algorithm", ["md5", "sha1"])
def test_md5_only_and_sha1_only_lists_match(conn, store, held, officer, algorithm):
    from noctornal_api.samples import ProhibitedContentMatch
    who = _analyst(conn)
    blob = payload(algorithm)
    import_list(conn, officer, listed(blob, algorithm=algorithm))
    with pytest.raises(ProhibitedContentMatch):
        service(conn, store, held).submit(blob, submitted_by=who)
    result = conn.execute(
        "SELECT matched_algorithms FROM lab.screening_result WHERE sample_id = %s",
        (_sample_id_by_sha(conn, blob),)).fetchone()
    assert result[0] == [algorithm]


def test_a_store_failure_still_records_and_alerts(conn, held, officer):
    from noctornal_api.samples import ProhibitedContentMatch

    class Broken(MemoryStore):
        def put(self, key, data):
            raise OSError("simulated outage")

    who = _analyst(conn)
    blob = payload("broken")
    import_list(conn, officer, listed(blob))
    with pytest.raises(ProhibitedContentMatch):
        service(conn, Broken(), held).submit(blob, submitted_by=who)
    sample_id = _sample_id_by_sha(conn, blob)
    _state, outcome, _pk, key_len, *_ = _row(conn, sample_id)
    assert outcome == "MATCH" and key_len == 0
    result = _results(conn, sample_id)[0]
    assert result[2] == "STORE_FAILED" and result[3] == "SENT"
    assert result[4]["store_failure"] == "OSError"
    assert len(notices(conn, officer, "SAMPLE_SCREENING_MATCH")) == 1


def test_resubmitting_matched_material_is_screened_before_the_duplicate_check(conn, store, held, officer):
    from noctornal_api.samples import ProhibitedContentMatch
    who = _analyst(conn)
    blob = payload("again")
    import_list(conn, officer, listed(blob))
    svc = service(conn, store, held)
    with pytest.raises(ProhibitedContentMatch):
        svc.submit(blob, submitted_by=who)
    with pytest.raises(ProhibitedContentMatch) as second:
        svc.submit(blob, submitted_by=who)
    assert second.value.alert_outcome == "COALESCED"
    rows = _results(conn, _sample_id_by_sha(conn, blob))
    assert [r[2] for r in rows] == ["PRESERVE", "ALREADY_ISOLATED"]
    assert len(notices(conn, officer, "SAMPLE_SCREENING_MATCH")) == 1


def test_a_duplicate_of_a_match_after_its_list_is_retired_gets_the_generic_refusal(conn, store, held, officer):
    from noctornal_api.samples import ProhibitedContentMatch, SampleError
    from noctornal_api.screening import ScreeningService
    who = _analyst(conn)
    blob = payload("retired")
    made = import_list(conn, officer, listed(blob))
    svc = service(conn, store, held)
    with pytest.raises(ProhibitedContentMatch):
        svc.submit(blob, submitted_by=who)
    ScreeningService(conn).retire_list(made["id"], actor_id=officer,
                                       reason="licence ended for this list",
                                       purge_entries=False)
    with pytest.raises(SampleError) as err:
        svc.submit(blob, submitted_by=who, visible_to_clearance="RED")
    assert "was not accepted" in str(err.value)
    assert "already held" not in str(err.value)


# --- held samples ---------------------------------------------------------------

def test_import_isolates_a_live_sample_in_the_request_and_the_worker_moves_its_bytes(conn, store, held, officer):
    from noctornal_api.screening import ScreeningService
    who = _analyst(conn)
    blob = payload("live")
    s = service(conn, store).submit(blob, submitted_by=who)
    out = import_list(conn, officer, listed(blob), samples=service(conn, store))
    assert out["rescan"]["matched"] == 1
    state, outcome, preserved_key, key_len, *_ = _row(conn, s.id)
    assert (state, outcome, preserved_key) == ("REJECTED", "MATCH", None)
    assert key_len > 0 and store.objects  # still in the working store
    assert _results(conn, s.id)[-1][:3] == ("LIST_IMPORT", "MATCH", "PRESERVE")
    counters = ScreeningService(conn, service(conn, store, held)).rescan(
        trigger="RESCAN", actor_id=None, move_bytes=True, budget_seconds=20)
    assert counters["preserved"] >= 1 and counters["pending"] == 0
    assert _row(conn, s.id)[2] is not None and store.objects == {}


def test_a_match_on_a_closed_case_is_preserved(conn, store, held, officer):
    who = _analyst(conn)
    case = make_case(conn, who)
    blob = payload("closed")
    s = service(conn, store).submit(blob, submitted_by=who, case_id=case)
    conn.execute('UPDATE core."case" SET status = \'CLOSED\', closed_at = now() '
                 'WHERE id = %s', (case,))
    import_list(conn, officer, listed(blob), samples=service(conn, store, held))
    assert service(conn, store, held).preserve_screened(s.id) == "preserved"
    assert _row(conn, s.id)[:2] == ("REJECTED", "MATCH")


def test_a_human_rejected_kept_sample_that_matches_is_marked_and_moved(conn, store, held, officer):
    who = _analyst(conn)
    blob = payload("kept")
    svc = service(conn, store, held)
    s = svc.submit(blob, submitted_by=who)
    svc.reject(s.id, actor_id=who, reason="not ours", purge_bytes=False)
    import_list(conn, officer, listed(blob), samples=svc)
    state, outcome, _pk, _k, _a, _seq, reason = _row(conn, s.id)
    assert (state, outcome, reason) == ("REJECTED", "MATCH", "not ours")
    assert svc.preserve_screened(s.id) == "preserved"


def test_a_destroyed_sample_that_matches_is_marked_with_no_bytes_and_is_not_pending(conn, store, held, officer, monkeypatch):
    from noctornal_api import screening
    monkeypatch.setenv("NOCTORNAL_REJECTED_SAMPLE_DISPOSITION", "destroy")
    who = _analyst(conn)
    blob = payload("gone")
    svc = service(conn, store, held)
    s = svc.submit(blob, submitted_by=who)
    svc.reject(s.id, actor_id=who, reason="destroy it")
    import_list(conn, officer, listed(blob), samples=svc)
    assert _results(conn, s.id)[-1][2] == "NO_BYTES"
    assert s.id not in _pending(conn)
    assert screening.sample_may_leave(conn, s.id) == (False, "match")


def test_a_preserved_sample_that_matches_voids_its_authorisations_on_every_door(conn, store, held, officer, monkeypatch):
    from noctornal_api.samples import SampleError
    monkeypatch.setenv("NOCTORNAL_BASE_URL", "https://app.example")
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    who = _analyst(conn)
    blob = payload("preserved")
    svc = service(conn, store, held)
    s = svc.submit(blob, submitted_by=who)
    svc.reject(s.id, actor_id=who, reason="preserve it")
    auth = svc.grant_preservation_authorisation(
        s.id, granted_to=owner, granted_by=officer,
        scope_note="Counsel asked for the loader to compare against the variant",
        legal_basis="Production order 2026-114")
    ticket = svc.issue_retrieval_ticket(s.id, actor_id=owner, clearance="RED",
                                        request_origin="https://app.example")
    import_list(conn, officer, listed(blob), samples=svc)
    # The grant: refused.
    with pytest.raises(SampleError, match="matched a prohibited-content list"):
        svc.grant_preservation_authorisation(
            s.id, granted_to=owner, granted_by=officer,
            scope_note="Counsel asked for the loader to compare again, later",
            legal_basis="Production order 2026-114")
    # The mint: refused as no such sample.
    with pytest.raises(SampleError, match="no such sample"):
        svc.issue_retrieval_ticket(s.id, actor_id=owner, clearance="RED",
                                   request_origin="https://app.example")
    # A ticket minted before the match is refused where every redemption
    # ends, and the retrieval itself is refused.
    assert ticket.raw
    with pytest.raises(SampleError, match="no such sample"):
        svc.retrieve_preserved(s.id, actor_id=owner, clearance="RED",
                               request_origin="https://samples.example")
    listing = svc.preservation_authorisations(s.id)
    assert listing[0]["id"] == str(auth)
    assert listing[0]["live"] is False
    assert listing[0]["void_reason"] == "screening_match"
    assert svc.live_preservation_authorisation(owner, s.id) is None
    assert _results(conn, s.id)[-1][4]["authorisations_voided"] == [str(auth)]
    officer_view = svc.preserved_for_authorisation(clearance="RED")
    mine = [x for x in officer_view if x["id"] == str(s.id)]
    assert mine and mine[0]["screening_match"] is True


def test_a_match_is_permanent(conn, store, held, officer):
    import psycopg

    from noctornal_api.screening import ScreeningService
    who = _analyst(conn)
    blob = payload("perm")
    svc = service(conn, store, held)
    s = svc.submit(blob, submitted_by=who)
    made = import_list(conn, officer, listed(blob), samples=svc)
    ScreeningService(conn, svc).retire_list(made["id"], actor_id=officer,
                                            reason="retired while testing",
                                            purge_entries=True)
    ScreeningService(conn, svc).rescan(trigger="RESCAN", actor_id=None,
                                       move_bytes=False, budget_seconds=20)
    assert _row(conn, s.id)[1] == "MATCH"
    with pytest.raises(psycopg.errors.RaiseException, match="permanent"):
        conn.execute("UPDATE lab.sample SET screening_outcome = 'NO_MATCH' "
                     "WHERE id = %s", (s.id,))


def test_a_new_list_rescreens_samples_already_no_match(conn, store, held, officer):
    who = _analyst(conn)
    blob = payload("later")
    svc = service(conn, store, held)
    import_list(conn, officer, listed(payload("first")), samples=svc)
    s = svc.submit(blob, submitted_by=who)
    assert s.screening_outcome == "NO_MATCH"
    import_list(conn, officer, listed(blob), samples=svc)
    assert _row(conn, s.id)[1] == "MATCH"


def test_a_submission_racing_an_import_is_caught_by_the_next_pass(conn, store, held, officer):
    from noctornal_api import screening
    who = _analyst(conn)
    first = import_list(conn, officer, listed(payload("a")), samples=service(conn, store))
    s = service(conn, store).submit(payload("b"), submitted_by=who)
    # As though a second list committed between this sample's screening and
    # its insert: its seq is behind the newest.
    blob2 = payload("c")
    import_list(conn, officer, listed(blob2), samples=service(conn, store),
                rescan_budget=0.001)
    conn.execute("UPDATE lab.sample SET screening_list_seq = %s WHERE id = %s",
                 (first["seq"], s.id))
    ok, why = screening.sample_may_leave(conn, s.id)
    assert (ok, why) == (False, "screening_behind")
    screening.ScreeningService(conn, service(conn, store)).rescan(
        trigger="RESCAN", actor_id=None, move_bytes=False, budget_seconds=20)
    assert screening.sample_may_leave(conn, s.id) == (True, "screened")


def test_a_preservation_failure_leaves_the_sample_pending_and_the_next_pass_completes_it(conn, store, officer):
    from noctornal_api import screening
    who = _analyst(conn)
    blob = payload("retry")
    s = service(conn, store).submit(blob, submitted_by=who)
    import_list(conn, officer, listed(blob), samples=service(conn, store))
    refusing = MemoryPreservation(fail=True)
    assert service(conn, store, refusing).preserve_screened(s.id) == "pending"
    assert s.id in _pending(conn)
    working = MemoryPreservation()
    out = screening.ScreeningService(conn, service(conn, store, working)).rescan(
        trigger="RESCAN", actor_id=None, move_bytes=True, budget_seconds=20)
    assert out["preserved"] >= 1
    assert s.id not in _pending(conn)
    # The kept key opens the held copy to the sample's own hash.
    from noctornal_api.samples import STORE_PRESERVATION
    data = service(conn, store, working)._verified_plaintext(
        s.id, actor_id=None, store=STORE_PRESERVATION)
    assert bytes(data) == blob


def _pending(conn):
    return {r[0] for r in conn.execute(
        """SELECT id FROM lab.sample WHERE screening_outcome = 'MATCH'
              AND preserved_key IS NULL AND octet_length(data_key_ciphertext) > 0
              AND screening_bytes_absent_at IS NULL""").fetchall()}


def test_an_absent_object_is_recorded_after_two_looks_and_the_key_is_kept(conn, officer, held, monkeypatch):
    from noctornal_api import screening
    who = _analyst(conn)
    blob = payload("absent")
    empty = MemoryStore()
    s = service(conn, empty).submit(blob, submitted_by=who)
    empty.objects.clear()   # the object is not there
    import_list(conn, officer, listed(blob), samples=service(conn, empty))
    svc = service(conn, empty, held)
    assert svc.preserve_screened(s.id) == "pending"      # first look
    assert svc.preserve_screened(s.id) == "pending"      # too soon
    monkeypatch.setattr(screening, "ABSENCE_RECHECK", timedelta(seconds=0))
    assert svc.preserve_screened(s.id) == "bytes_not_found"
    _st, _o, preserved_key, key_len, absent, *_ = _row(conn, s.id)
    assert preserved_key is None and key_len > 0 and absent is not None
    assert s.id not in _pending(conn)
    events = [c[2].get("event") for c in _custody(conn, s.id)]
    assert "screening_bytes_not_found" in events and "screening_bytes_absent" in events
    assert svc.get(s.id).bytes_disposition == "not_found"


def _detonation(conn, sample_id, requester, status, **kw):
    fields = {"mode": "SUBMIT", "provider": "capev2", "target_key": "cape",
              "target_host": "cape.lab:443", "target_ceiling": "AMBER",
              "egress_route": "integration:sandbox", "network_route": "none",
              "route_class": "ISOLATED", "status": status}
    if status in ("SUBMITTED",):
        fields["submitted_at"] = "now()"
    fields.update(kw)
    cols = ", ".join(["sample_id", "target", "exposure_level", "requested_by"]
                     + list(fields))
    vals = ["%s", "'cape'", "'NONE'", "%s"] + [
        v if v == "now()" else f"'{v}'" for v in fields.values()]
    return conn.execute(
        f"INSERT INTO lab.detonation ({cols}) VALUES ({', '.join(vals)}) RETURNING id",
        (sample_id, requester)).fetchone()[0]


def test_waiting_detonations_are_refused_and_a_sent_one_is_named(conn, store, held, officer):
    who = _analyst(conn)
    blob = payload("det")
    s = service(conn, store).submit(blob, submitted_by=who)
    queued = _detonation(conn, s.id, who, "QUEUED")
    sent = _detonation(conn, s.id, who, "SUBMITTED", target_key="cape2",
                       target_host="cape2.lab:443")
    import_list(conn, officer, listed(blob), samples=service(conn, store))
    rows = dict(conn.execute("SELECT id, status FROM lab.detonation WHERE sample_id = %s",
                             (s.id,)).fetchall())
    assert rows[queued] == "REFUSED" and rows[sent] == "SUBMITTED"
    detail = _results(conn, s.id)[-1][4]
    assert detail["detonations_refused"] == [str(queued)]
    assert [d["target"] for d in detail["detonations_sent"]] == ["cape2"]


def test_a_failing_detonation_update_never_undoes_the_isolation(conn, store, officer):
    who = _analyst(conn)
    blob = payload("detfail")
    s = service(conn, store).submit(blob, submitted_by=who)
    _detonation(conn, s.id, who, "QUEUED")
    conn.execute("""CREATE FUNCTION pg_temp.refuse() RETURNS trigger LANGUAGE plpgsql
                    AS $$ BEGIN RAISE EXCEPTION 'simulated'; END $$""")
    conn.execute("CREATE TRIGGER scr_refuse BEFORE UPDATE ON lab.detonation "
                 "FOR EACH ROW EXECUTE FUNCTION pg_temp.refuse()")
    try:
        import_list(conn, officer, listed(blob), samples=service(conn, store))
    finally:
        conn.execute("DROP TRIGGER scr_refuse ON lab.detonation")
    assert _row(conn, s.id)[1] == "MATCH"
    assert _results(conn, s.id)[-1][4]["detonation_refusal_failed"]


def test_a_queued_static_run_is_never_claimed_for_a_match(conn, store, officer):
    from noctornal_api import lab_triage
    who = _analyst(conn)
    blob = payload("queued")
    s = service(conn, store).submit(blob, submitted_by=who)
    run = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                       "AND status = 'QUEUED'", (s.id,)).fetchone()[0]
    import_list(conn, officer, listed(blob), samples=service(conn, store))
    claimed, _skipped = lab_triage.claim(conn, lab_triage.settings_or_default(),
                                         run_id=run)
    assert claimed is None
    status = conn.execute("SELECT status FROM lab.static_run WHERE id = %s",
                          (run,)).fetchone()[0]
    assert status in ("SKIPPED", "QUEUED")


def test_two_passes_do_not_overlap(conn, store):
    from noctornal_api.db import connect
    from noctornal_api.screening import ScreeningService
    other = connect()
    try:
        other.execute("SELECT pg_advisory_lock(hashtextextended('noctornal.sample_screen', 0))")
        out = ScreeningService(conn, service(conn, store)).rescan(
            trigger="RESCAN", actor_id=None, move_bytes=False, budget_seconds=5)
        assert out == {"skipped": "another screening pass is running"}
    finally:
        other.close()


def test_a_pass_needs_a_finite_budget(conn):
    from noctornal_api.screening import ScreeningService
    with pytest.raises(ValueError):
        ScreeningService(conn).rescan(trigger="RESCAN", actor_id=None,
                                      move_bytes=False, budget_seconds=None)


def test_a_pass_walks_past_a_match_that_keeps_failing_and_screens_the_rest(conn, store, officer, monkeypatch):
    from noctornal_api.samples import SampleService
    who = _analyst(conn)
    bad, fine = payload("bad"), payload("fine")
    a = service(conn, store).submit(bad, submitted_by=who)
    b = service(conn, store).submit(payload("clean"), submitted_by=who)
    c = service(conn, store).submit(fine, submitted_by=who)
    real = SampleService.reject_by_screening

    def flaky(self, sample_id, **kw):
        if sample_id == a.id:
            raise RuntimeError("simulated")
        return real(self, sample_id, **kw)

    monkeypatch.setattr(SampleService, "reject_by_screening", flaky)
    out = import_list(conn, officer, listed(bad, fine), samples=service(conn, store))
    assert out["rescan"]["failed"] == 1 and out["rescan"]["matched"] == 1
    assert _row(conn, a.id)[1] == "NOT_SCREENED"
    assert _row(conn, b.id)[1] == "NO_MATCH"
    assert _row(conn, c.id)[1] == "MATCH"


# --- alerts ------------------------------------------------------------------------

def test_the_officer_alert_is_urgent_green_caseless_and_content_free(conn, store, held, officer):
    from noctornal_api.samples import ProhibitedContentMatch
    who = _analyst(conn)
    case = make_case(conn, who)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s', (case,)).fetchone()[0]
    blob = payload("content")
    import_list(conn, officer, listed(blob), name="Provider list A")
    with pytest.raises(ProhibitedContentMatch):
        service(conn, store, held).submit(blob, submitted_by=who, case_id=case,
                                          original_filename="evil-name.exe")
    (subject, summary, body, classification, case_id, priority, _obj), = notices(
        conn, officer, "SAMPLE_SCREENING_MATCH")
    assert (classification, case_id, priority) == ("GREEN", None, 1)
    text = subject + summary + body
    for secret in (code, "evil-name.exe", hashlib.sha256(blob).hexdigest(),
                   hashlib.sha1(blob).hexdigest(), hashlib.md5(blob).hexdigest()):
        assert secret not in text
    assert "Provider list A" in body


def test_an_officer_with_an_open_alert_is_not_alerted_again_within_the_hour(conn, store, officer):
    who = _analyst(conn)
    blobs = [payload(f"bulk{i}") for i in range(5)]
    for blob in blobs:
        service(conn, store).submit(blob, submitted_by=who)
    import_list(conn, officer, listed(*blobs), samples=service(conn, store))
    assert len(notices(conn, officer, "SAMPLE_SCREENING_MATCH")) == 1
    outcomes = sorted(r[0] for r in conn.execute(
        """SELECT alert_outcome FROM lab.screening_result r
             JOIN lab.sample s ON s.id = r.sample_id
            WHERE s.sha256 = ANY(%s)""",
        ([hashlib.sha256(b).digest() for b in blobs],)).fetchall())
    assert outcomes.count("SENT") == 1 and outcomes.count("COALESCED") == 4


def test_the_designated_persons_account_is_alerted_once(conn, store, held, monkeypatch):
    from noctornal_api.samples import ProhibitedContentMatch
    person = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    email = conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                         (person,)).fetchone()[0]
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", email.upper())
    who = _analyst(conn)
    blob = payload("dp")
    import_list(conn, person, listed(blob))
    with pytest.raises(ProhibitedContentMatch):
        service(conn, store, held).submit(blob, submitted_by=who)
    assert len(notices(conn, person, "SAMPLE_SCREENING_MATCH")) == 1
    assert _results(conn, _sample_id_by_sha(conn, blob))[0][4][
        "designated_person_told"] is True


def test_the_case_owner_is_told_at_the_samples_labels(conn, store, officer):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",), compartments=("SCR-A",))
    blind = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    who = _analyst(conn, compartments=("SCR-B",))
    told = make_case(conn, owner)
    untold = make_case(conn, blind)
    plain, restricted = payload("plain"), payload("restricted")
    s1 = service(conn, store).submit(plain, submitted_by=who, case_id=told)
    s2 = service(conn, store).submit(restricted, submitted_by=who, case_id=untold,
                                     compartments=frozenset({"SCR-B"}))
    import_list(conn, officer, listed(plain, restricted), samples=service(conn, store))
    assert len(notices(conn, owner, "SAMPLE_WITHDRAWN")) == 1
    assert notices(conn, blind, "SAMPLE_WITHDRAWN") == []
    assert _results(conn, s1.id)[-1][4]["case_owner_told"] is True
    assert _results(conn, s2.id)[-1][4]["case_owner_told"] is False


def test_a_notification_failure_does_not_undo_the_isolation(conn, store, held, officer, monkeypatch):
    from noctornal_api import notify_events
    from noctornal_api.samples import ProhibitedContentMatch

    def broken(*_a, **_k):
        raise RuntimeError("simulated")

    monkeypatch.setattr(notify_events, "screening_match", broken)
    who = _analyst(conn)
    blob = payload("notify")
    import_list(conn, officer, listed(blob))
    with pytest.raises(ProhibitedContentMatch) as err:
        service(conn, store, held).submit(blob, submitted_by=who)
    assert err.value.alert_outcome == "FAILED"
    assert "tell" in str(err.value) and "yourself now" in str(err.value)
    sample_id = _sample_id_by_sha(conn, blob)
    assert _row(conn, sample_id)[1] == "MATCH"
    assert _results(conn, sample_id)[0][3] == "FAILED"


def test_zero_officers_is_recorded_and_the_refusal_says_tell_them_yourself(conn, store, held, officer, monkeypatch):
    from noctornal_api import notify_events
    from noctornal_api.samples import ProhibitedContentMatch
    monkeypatch.setattr(notify_events, "_screening_recipients", lambda _c: [])
    who = _analyst(conn)
    blob = payload("nobody")
    import_list(conn, officer, listed(blob))
    with pytest.raises(ProhibitedContentMatch) as err:
        service(conn, store, held).submit(blob, submitted_by=who)
    assert err.value.alert_outcome == "NONE_REACHED"
    assert "has been alerted" not in str(err.value)
    assert "yourself now" in str(err.value)


# --- isolation --------------------------------------------------------------------

def test_matched_samples_are_hidden_from_every_lab_reader(conn, store, officer, monkeypatch):
    from noctornal_api import lab_similarity
    from noctornal_api.samples import QUEUE_STATES, SampleError
    monkeypatch.setenv("NOCTORNAL_BASE_URL", "https://app.example")
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    who = _analyst(conn)
    blob = payload("hidden")
    svc = service(conn, store)
    s = svc.submit(blob, submitted_by=who)
    import_list(conn, officer, listed(blob), samples=svc)
    for state in QUEUE_STATES:
        assert s.id not in {x.id for x in svc.queue(states=(state,), clearance="RED")}
    assert svc.visible(s.id, clearance="RED") is None
    with pytest.raises(SampleError, match="no such sample"):
        svc._downloadable(s.id, clearance="RED")
    with pytest.raises(SampleError, match="no such sample"):
        svc.issue_download_ticket(s.id, actor_id=who, clearance="RED",
                                  request_origin="https://app.example")
    out = lab_similarity.similar(
        conn, hashes={"imphash": "0" * 32}, by="imphash",
        thresholds=lab_similarity.Thresholds(
            lab_similarity.SSDEEP_MIN_DEFAULT, lab_similarity.TLSH_MAX_DEFAULT,
            lab_similarity.LIMIT_DEFAULT, True),
        clearance="RED", compartments=frozenset())
    assert str(s.id) not in str(out)
    # The row is still there for the officer's opt-out reader.
    from noctornal_api.samples import lab_gate
    assert conn.execute(
        f"""SELECT count(*) FROM lab.sample s LEFT JOIN core."case" c
             ON c.id = s.case_id WHERE s.id = %(id)s
            AND {lab_gate(exclusions=False)}""",
        {"id": s.id, "gate_clearance": "RED", "gate_compartments": []}
    ).fetchone()[0] == 1


def test_assign_record_analysis_request_detonation_propose_and_reject_refuse_a_match(conn, store, officer):
    from noctornal_api.samples import SampleError
    who = _analyst(conn)
    blob = payload("belts")
    svc = service(conn, store)
    s = svc.submit(blob, submitted_by=who)
    import_list(conn, officer, listed(blob), samples=svc)
    for call in (lambda: svc.assign(s.id, analyst_id=who, actor_id=who),
                 lambda: svc.record_analysis(s.id, analyst_id=who, kind="MANUAL_RE"),
                 lambda: svc.request_detonation(s.id, requested_by=who,
                                                target="x", exposure_level="NONE"),
                 lambda: svc.propose_extracted_selector(svc.get(s.id), uuid4(), 0,
                                                        actor_id=who)):
        with pytest.raises(SampleError, match="no such sample"):
            call()
    with pytest.raises(SampleError, match="already rejected"):
        svc.reject(s.id, actor_id=who, reason="again")


# --- lists -------------------------------------------------------------------------

def test_import_is_refused_without_the_policy_or_the_hash_set_authority(conn, officer, monkeypatch):
    from noctornal_api.screening import ScreeningRefused
    monkeypatch.delenv("NOCTORNAL_HASH_SET_AUTHORITY")
    with pytest.raises(ScreeningRefused, match="NOCTORNAL_HASH_SET_AUTHORITY"):
        import_list(conn, officer, listed(payload()))
    declare(monkeypatch)
    monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY")
    with pytest.raises(ScreeningRefused, match="ingest policy"):
        import_list(conn, officer, listed(payload()))


def test_import_is_one_transaction_and_counts_distinct_entries(conn, officer):
    from noctornal_api.screening import ScreeningError
    blob = payload("dup")
    text = listed(blob, blob, blob) + listed(payload("x"))
    made = import_list(conn, officer, text)
    assert made["entry_count"] == 2
    stored = conn.execute("SELECT count(*) FROM lab.screening_hash WHERE list_id = %s",
                          (made["id"],)).fetchone()[0]
    assert stored == 2
    before = conn.execute("SELECT count(*) FROM lab.screening_list").fetchone()[0]
    # The header, the entry and the random comment are lines 1 to 3.
    with pytest.raises(ScreeningError, match="line 4"):
        import_list(conn, officer, listed(payload("y")) + b"not a hash\n")
    assert conn.execute("SELECT count(*) FROM lab.screening_list").fetchone()[0] == before


def test_an_empty_list_is_refused(conn, officer):
    from noctornal_api.screening import ScreeningError
    with pytest.raises(ScreeningError, match="no entries"):
        import_list(conn, officer, b"# only a comment\n\n")


def test_a_duplicate_active_list_is_refused(conn, officer):
    from noctornal_api.screening import ScreeningConflict
    text = listed(payload("same"))
    import_list(conn, officer, text)
    with pytest.raises(ScreeningConflict, match="already imported"):
        import_list(conn, officer, text)


def test_retire_deletes_nothing_and_the_purge_runs_in_batches(conn, officer, monkeypatch):
    from noctornal_api import screening
    svc = screening.ScreeningService(conn)
    made = import_list(conn, officer, listed(*[payload(str(i)) for i in range(7)]))
    other = import_list(conn, officer, listed(payload("keep")))
    svc.retire_list(made["id"], actor_id=officer, reason="licence ended today",
                    purge_entries=False)
    count = conn.execute("SELECT count(*) FROM lab.screening_hash WHERE list_id = %s",
                         (made["id"],)).fetchone()[0]
    assert count == 7
    # Asked for later, once.
    svc.request_purge(made["id"], actor_id=officer)
    with pytest.raises(screening.ScreeningConflict):
        svc.request_purge(made["id"], actor_id=officer)
    monkeypatch.setattr(screening, "PURGE_BATCH", 3)
    assert svc.purge_pending(budget_seconds=20) == 7
    row = conn.execute("SELECT entries_purged_at FROM lab.screening_list WHERE id = %s",
                       (made["id"],)).fetchone()
    assert row[0] is not None
    assert conn.execute("SELECT count(*) FROM lab.screening_hash WHERE list_id = %s",
                        (other["id"],)).fetchone()[0] == 1
    # An active list cannot have its purge asked for.
    with pytest.raises(screening.ScreeningConflict):
        svc.request_purge(other["id"], actor_id=officer)


def test_a_live_lists_entries_cannot_be_deleted_or_updated(conn, officer):
    import psycopg
    made = import_list(conn, officer, listed(payload("live-list")))
    with pytest.raises(psycopg.errors.RaiseException, match="retired with its purge"):
        conn.execute("DELETE FROM lab.screening_hash WHERE list_id = %s", (made["id"],))
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE lab.screening_hash SET digest = digest WHERE list_id = %s",
                     (made["id"],))


def test_list_rows_are_never_deleted_and_only_retirement_updates(conn, officer):
    import psycopg
    made = import_list(conn, officer, listed(payload("rows")))
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
        conn.execute("DELETE FROM lab.screening_list WHERE id = %s", (made["id"],))
    with pytest.raises(psycopg.errors.RaiseException, match="history"):
        conn.execute("UPDATE lab.screening_list SET name = 'x' WHERE id = %s",
                     (made["id"],))


def test_results_and_reviews_refuse_update_delete_and_truncate(conn, store, held, officer):
    import psycopg

    from noctornal_api.samples import ProhibitedContentMatch
    from noctornal_api.screening import ScreeningService
    who = _analyst(conn)
    blob = payload("ledger")
    import_list(conn, officer, listed(blob))
    with pytest.raises(ProhibitedContentMatch) as err:
        service(conn, store, held).submit(blob, submitted_by=who)
    result = err.value.result_id
    ScreeningService(conn).review(result, actor_id=officer, action="ACKNOWLEDGED")
    for sql in ("UPDATE lab.screening_result SET trigger = trigger WHERE id = %s",
                "DELETE FROM lab.screening_result WHERE id = %s",
                "UPDATE lab.screening_review SET note = 'x' WHERE result_id = %s",
                "DELETE FROM lab.screening_review WHERE result_id = %s"):
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute(sql, (result,))
    for table in ("screening_result", "screening_review"):
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(f"TRUNCATE lab.{table} CASCADE")


def test_a_referral_or_outside_disposal_needs_a_reference(conn, store, held, officer):
    import psycopg

    from noctornal_api.samples import ProhibitedContentMatch
    from noctornal_api.screening import ScreeningError, ScreeningService
    who = _analyst(conn)
    blob = payload("review")
    import_list(conn, officer, listed(blob))
    with pytest.raises(ProhibitedContentMatch) as err:
        service(conn, store, held).submit(blob, submitted_by=who)
    svc = ScreeningService(conn)
    for action in ("REFERRED", "DISPOSED_OUTSIDE"):
        with pytest.raises(ScreeningError, match="reference"):
            svc.review(err.value.result_id, actor_id=officer, action=action,
                       note="no reference given")
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO lab.screening_review (result_id, reviewed_by, action)
               VALUES (%s, %s, 'REFERRED')""", (err.value.result_id, officer))
    out = svc.review(err.value.result_id, actor_id=officer, action="REFERRED",
                     reference="NCMEC report 2026-001")
    assert out["action"] == "REFERRED"


# --- the one reader of "may this leave" -------------------------------------------

def test_a_sample_leaves_only_when_screened_no_match_against_every_active_list(conn, store, held, officer, monkeypatch):
    from noctornal_api import screening
    who = _analyst(conn)
    early = service(conn, store).submit(payload("early"), submitted_by=who)
    assert screening.sample_may_leave(conn, early.id) == (False, "no_active_list")
    blob = payload("bad")
    matched = service(conn, store).submit(blob, submitted_by=who)
    import_list(conn, officer, listed(blob), samples=service(conn, store))
    clean = service(conn, store).submit(payload("clean"), submitted_by=who)
    assert screening.sample_may_leave(conn, clean.id) == (True, "screened")
    assert screening.sample_may_leave(conn, matched.id) == (False, "match")
    rejected = service(conn, store, held).submit(payload("rej"), submitted_by=who)
    service(conn, store, held).reject(rejected.id, actor_id=who, reason="r",
                                      purge_bytes=False)
    assert screening.sample_may_leave(conn, rejected.id) == (False, "rejected")
    conn.execute("UPDATE lab.sample SET screening_outcome = 'NOT_SCREENED', "
                 "screened_at = NULL, screening_list_seq = NULL WHERE id = %s",
                 (clean.id,))
    assert screening.sample_may_leave(conn, clean.id) == (False, "not_screened")
    monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY")
    assert screening.sample_may_leave(conn, clean.id) == (False, "policy_undeclared")
    for reason in ("policy_undeclared", "no_active_list", "rejected",
                   "not_screened", "screening_behind", "match"):
        assert screening.SAMPLE_MAY_LEAVE_SENTENCES[reason]


def test_the_derived_gaps_follow_the_outcome(conn, store, officer):
    who = _analyst(conn)
    svc = service(conn, store)
    before = svc.submit(payload("g1"), submitted_by=who)
    import_list(conn, officer, listed(payload("unrelated")), samples=svc)
    after = svc.submit(b"PK\x03\x04" + uuid4().bytes * 4, submitted_by=who)
    gaps = svc.derived_gaps([svc.get(before.id), svc.get(after.id)])
    assert [g["step"] for g in gaps[str(before.id)]] == ["prohibited_content_perceptual"]
    assert [g["step"] for g in gaps[str(after.id)]] == [
        "prohibited_content_perceptual", "prohibited_content_archive_members"]


# --- the verifier's points (2026-09-24) ------------------------------------------

def test_a_retirement_or_a_purge_request_never_stands_without_its_audit_row(conn, officer, monkeypatch):
    """Each is one transaction with its audit row: the router's connection
    autocommits each statement, so until 2026-09-24 a failed audit insert
    left a retirement or a purge request nobody could account for."""
    from noctornal_api import screening
    made = import_list(conn, officer, listed(payload("atomic")))
    real = screening._audit

    def refuses(c, action, **kw):
        if action in ("SCREENING_LIST_RETIRED", "SCREENING_LIST_PURGE_REQUESTED"):
            raise RuntimeError("the audit insert failed")
        return real(c, action, **kw)

    def state():
        return conn.execute(
            """SELECT retired_at IS NOT NULL, purge_requested
                 FROM lab.screening_list WHERE id = %s""", (made["id"],)).fetchone()

    svc = screening.ScreeningService(conn)
    monkeypatch.setattr(screening, "_audit", refuses)
    with pytest.raises(RuntimeError):
        svc.retire_list(made["id"], actor_id=officer,
                        reason="the licence ended today", purge_entries=True)
    assert state() == (False, False)
    monkeypatch.setattr(screening, "_audit", real)
    svc.retire_list(made["id"], actor_id=officer, reason="the licence ended today",
                    purge_entries=False)
    monkeypatch.setattr(screening, "_audit", refuses)
    with pytest.raises(RuntimeError):
        svc.request_purge(made["id"], actor_id=officer)
    assert state() == (True, False)


def test_a_bytes_not_found_row_needs_a_review_recorded_after_the_absence(conn, officer, held, monkeypatch):
    """Only a recorded review ends the question, and a
    review made before the absence was recorded does not answer it."""
    from noctornal_api import screening
    who = _analyst(conn)
    blob = payload("absent-review")
    empty = MemoryStore()
    s = service(conn, empty).submit(blob, submitted_by=who)
    empty.objects.clear()
    import_list(conn, officer, listed(blob), samples=service(conn, empty))
    result = conn.execute(
        """SELECT id FROM lab.screening_result WHERE sample_id = %s
              AND outcome = 'MATCH'""", (s.id,)).fetchone()[0]
    officers = screening.ScreeningService(conn)
    officers.review(result, actor_id=officer, action="ACKNOWLEDGED")
    monkeypatch.setattr(screening, "ABSENCE_RECHECK", timedelta(seconds=0))
    svc = service(conn, empty, held)
    assert svc.preserve_screened(s.id) == "pending"            # first look
    assert svc.preserve_screened(s.id) == "bytes_not_found"    # second look

    def now_of():
        rows = officers.results(clearance="RED", compartments=frozenset())
        return {r["result_id"]: r["disposition_now"] for r in rows}[str(result)]

    unanswered = screening.state(conn).bytes_not_found
    assert unanswered >= 1
    assert now_of() == "bytes_not_found"
    detail = officers.result_detail(result, clearance="RED", compartments=frozenset())
    assert detail["disposition_now"] == "bytes_not_found"
    officers.review(result, actor_id=officer, action="REFERRED",
                    reference="STORE-TICKET-4411", note="storage admin checked")
    assert screening.state(conn).bytes_not_found == unanswered - 1
    assert now_of() == "bytes_not_found_reviewed"
    detail = officers.result_detail(result, clearance="RED", compartments=frozenset())
    assert detail["disposition_now"] == "bytes_not_found_reviewed"


def test_the_policy_block_carries_the_last_pass_within_its_window(conn, officer):
    from noctornal_api import screening
    import_list(conn, officer, listed(payload("policy-pass")))
    block = screening.policy_block(conn)
    assert block["active_lists"] >= 1 and block["last_pass_at"] is not None
    assert block["last_pass_window_hours"] == 24
    # Counts and a time only: no list is named.
    assert set(block) == {"active_lists", "algorithms", "exact_hash_only",
                          "authority_declared", "last_pass_at",
                          "last_pass_window_hours", "sentence"}
