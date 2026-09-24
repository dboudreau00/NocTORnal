"""An exhibit's storage lock follows its case's retention date
(x-lock-extension, 2026-09-24), and the inspector's exhibit list states
the lock the way the Evidence pane's card does (x-inspector-chips).

Each exhibit was written under a COMPLIANCE lock for a fixed period from
lodging (365 days by default). Nothing lengthened it, so a case whose
retention ran longer kept exhibits the store would delete from day 366
while the case date, the register and the chip all read as held. Now:

- `PATCH /cases/{id}` with a retention date lengthens every live
  exhibit's lock to the start of that date (the instant the purge treats
  the case as due), writes a LOCK_EXTENDED custody row, and reports what
  it did. A lock that could not be lengthened is reported and audited,
  and never undoes the date.

The verifier's round (2026-09-24) found three gaps, each held here:

- DISCLOSURE: the report counted every exhibit, so an AMBER owner whose
  register shows one exhibit was told three were lengthened. It now
  counts only those within the caller's ceiling; every one is still
  locked.
- OVERCLAIM: only an extension moved a lock, so an exhibit lodged into a
  case already retained past a year kept the year (OP-NIGHTJAR-26's .eml,
  locked to 2027-09-23 in a case retained to 2028-12-31) while the policy
  said the lock followed the case. A lodging now locks to the case's date;
  an older lock short of the case is counted and said
  (`lock_short_of_case`, `locks_short`), and `POST .../evidence/locks`
  lengthens it.
- IRREVERSIBILITY: one `case.update` holder typing 2208 would lock every
  exhibit for ever. A lock is set at most `LOCK_HORIZON` ahead in one
  step, and the report says when the horizon stopped it (`capped`).

The service tests use a stand-in store and a transaction that is rolled
back. The HTTP tests commit under the email prefix `lxh-` and remove what
they wrote. The one test that measures the real store is gated on
MINIO_ENDPOINT and locks its object for seconds, under the prefix
`test_evidence_lock_live_pg.py` sweeps. `tests/conftest.py` sets the
horizon to a day; the tests that need a real one set it here.
"""
from __future__ import annotations

import os
from datetime import date, datetime, time, timedelta, timezone
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs a migrated database")

MINIO = os.environ.get("MINIO_ENDPOINT", "")
API = "/api/v1"
TEN_YEARS = timedelta(days=3650)


@pytest.fixture()
def conn():
    import psycopg

    from noctornal_api.db import dsn

    c = psycopg.connect(dsn())
    try:
        yield c
    finally:
        c.rollback()
        c.close()


@pytest.fixture()
def horizon(monkeypatch):
    """The deployment's horizon, as a test sets it: ten years unless the
    test asks for another. Read at call time from `evidence`, so every
    helper that follows the case sees the same one."""
    import noctornal_api.evidence as evidence

    def set_to(delta: timedelta) -> timedelta:
        monkeypatch.setattr(evidence, "LOCK_HORIZON", delta)
        return delta
    set_to(TEN_YEARS)
    return set_to


class Refused(Exception):
    code = "AccessDenied"


class LockStore:
    """The storage half, as `EvidenceService.extend_locks` calls it: an
    end instant per key, lengthened only, and refusals for named keys.
    `put` and `get` for a lodging."""

    bucket = "test"

    def __init__(self, held=None, refuse=()):
        self.held: dict[str, datetime | None] = dict(held or {})
        self.refuse = set(refuse)
        self.calls: list[tuple[str, datetime]] = []
        self.objects: dict[str, bytes] = {}

    def put(self, key, data, *, media_type, retain_until):
        self.objects[key] = data
        self.held[key] = retain_until

    def get(self, key):
        return self.objects[key]

    def extend_lock(self, key, until):
        from noctornal_api.evidence import LockExtension
        self.calls.append((key, until))
        if key in self.refuse:
            raise Refused("policy denies PutObjectRetention")
        before = self.held.get(key)
        if before is not None and before >= until:
            return LockExtension(key=key, versions=1, extended=0, previous=before)
        self.held[key] = until
        return LockExtension(key=key, versions=1, extended=1, previous=before)


def _user(conn, clearance="RED", compartments=()):
    for key in compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, key))
    return conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash,
                                     tlp_clearance, compartments)
           VALUES (%s, 'Lock Owner', 'x', %s, %s) RETURNING id""",
        (f"lx-{uuid4().hex[:8]}@noctornal.test", clearance,
         list(compartments))).fetchone()[0]


def _case(conn, uid, retention="2027-06-01", status="ACTIVE"):
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due, status)
           VALUES (%s, %s, 'Lock IT', 'AMBER', %s, 'dev', %s, '2027-01-01', %s)""",
        (case_id, f"OP-LX-{uuid4().hex[:6]}", uid, retention, status))
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'CASE_OWNER', %s)""", (case_id, uid, uid))
    return case_id


def _exhibit(conn, case_id, uid, *, lock_day=date(2027, 1, 10), purged=False,
             title="exhibit.png", classification="AMBER", compartments=()):
    from noctornal_api.evidence import EvidenceService
    key = f"lx/{uuid4().hex}"
    ev = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification, compartments,
                acquisition_method, acquired_at, acquired_by, retention_until,
                purged_at)
           VALUES (%s, %s, 'image/png', 10, %s, %s, %s, 'test', %s, %s,
                   'MANUAL_UPLOAD', now(), %s, %s, CASE WHEN %s THEN now() END)
           RETURNING id""",
        (case_id, title, os.urandom(32), os.urandom(32), key, classification,
         list(compartments), uid, lock_day, purged)).fetchone()[0]
    lodged = datetime.combine(lock_day, time(3, 2, 3), tzinfo=timezone.utc)
    EvidenceService(conn, None)._custody(
        ev, "ACQUIRED", uid, hash_verified=True,
        detail={"sha256": "ab", "bytes": 10, "lock_ends_at": lodged.isoformat()})
    return ev, key, lodged


def _midnight(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=timezone.utc)


def _as(uid):
    from noctornal_api.http.deps import CurrentUser
    return CurrentUser(user_id=uid, session_id=uuid4(),
                       session_mfa_at=datetime.now(timezone.utc))


def _extended(conn, ev):
    return conn.execute(
        """SELECT detail FROM core.evidence_custody
            WHERE evidence_id = %s AND action = 'LOCK_EXTENDED'""", (ev,)).fetchall()


# --- the service ----------------------------------------------------------

def test_an_extension_lengthens_each_live_lock_and_records_it(conn, horizon):
    from noctornal_api.evidence import EvidenceService
    uid = _user(conn)
    case_id = _case(conn, uid)
    short, short_key, short_end = _exhibit(conn, case_id, uid)
    long_, long_key, _ = _exhibit(conn, case_id, uid, lock_day=date(2031, 1, 1))
    refused, refused_key, _ = _exhibit(conn, case_id, uid)
    gone, gone_key, _ = _exhibit(conn, case_id, uid, purged=True)
    store = LockStore(held={short_key: short_end,
                            long_key: _midnight(date(2031, 1, 1))},
                      refuse={refused_key})
    day = date(2029, 3, 1)

    report = EvidenceService(conn, store).extend_locks(case_id, day, uid)

    assert report == {"lock_ends_at": _midnight(day).isoformat(), "capped": False,
                      "exhibits": 3, "extended": 1, "already_held": 1,
                      "failed": 1, "date_passed": False}
    assert gone_key not in {k for k, _ in store.calls}, "a purged exhibit has no bytes"
    assert all(until == _midnight(day) for _, until in store.calls), (
        "the lock ends where the purge starts: the retention day at 00:00 UTC")
    # The lengthened exhibit: its day, a custody row, an audit row.
    assert conn.execute("SELECT retention_until FROM core.evidence WHERE id = %s",
                        (short,)).fetchone()[0] == day
    [(detail,)] = _extended(conn, short)
    assert detail["lock_ends_at"] == _midnight(day).isoformat()
    assert detail["previous_lock_ends_at"] == short_end.isoformat()
    assert detail["case_retention_until"] == day.isoformat()
    assert detail["capped_at_horizon"] is False
    # Already held longer: left alone, day unchanged, no row.
    assert conn.execute("SELECT retention_until FROM core.evidence WHERE id = %s",
                        (long_,)).fetchone()[0] == date(2031, 1, 1)
    # Refused: audited, not raised, and its record still says what it had.
    failed = conn.execute(
        """SELECT outcome, detail->>'reason' FROM audit.event
            WHERE object_id = %s AND action = 'EVIDENCE_LOCK_EXTENSION_FAILED'""",
        (refused,)).fetchone()
    assert failed == ("FAILED", "AccessDenied")
    assert conn.execute("SELECT retention_until FROM core.evidence WHERE id = %s",
                        (refused,)).fetchone()[0] == date(2027, 1, 10)


def test_without_a_store_every_exhibit_is_reported_and_nothing_raises(conn, horizon):
    from noctornal_api.evidence import EvidenceService
    uid = _user(conn)
    case_id = _case(conn, uid)
    _exhibit(conn, case_id, uid)
    report = EvidenceService(conn, None).extend_locks(case_id, date(2029, 1, 1), uid)
    assert report["failed"] == 1 and report["extended"] == 0


def test_a_date_already_reached_sets_no_lock(conn, horizon):
    from noctornal_api.evidence import EvidenceService
    uid = _user(conn)
    case_id = _case(conn, uid)
    _exhibit(conn, case_id, uid)
    store = LockStore()
    report = EvidenceService(conn, store).extend_locks(case_id, date(2020, 1, 1), uid)
    assert report["date_passed"] is True and store.calls == []


# --- the verifier's round: disclosure --------------------------------------

def test_the_answer_counts_only_the_exhibits_the_caller_may_see(
        conn, horizon, monkeypatch):
    """An AMBER Lead investigator's register shows one exhibit; the case
    holds three (one RED, one in a compartment they are not read into).
    Saving the date locks all three and tells them about one, a refusal on
    a hidden one included, which only the audit log names. Re-saving the
    same date says the same thing: before this it repeated the true total
    on demand."""
    import noctornal_api.evidence as evidence
    from noctornal_api.http.routers.cases import UpdateCaseBody, update_case
    from noctornal_api.http.routers.evidence import exhibit_register
    uid = _user(conn, clearance="AMBER")
    case_id = _case(conn, uid)
    # Rolled back with everything else; a compartment must be registered
    # before an exhibit may carry it.
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                 "ON CONFLICT (key) DO NOTHING", ("LX-WALL", "LX-WALL (lock test)"))
    seen, seen_key, seen_end = _exhibit(conn, case_id, uid)
    red, red_key, _ = _exhibit(conn, case_id, uid, classification="RED")
    walled, walled_key, _ = _exhibit(conn, case_id, uid, compartments=("LX-WALL",))
    store = LockStore(held={seen_key: seen_end}, refuse={walled_key})
    monkeypatch.setattr(evidence, "EvidenceStorage", lambda: store)

    ext = update_case(case_id, UpdateCaseBody(retention_until=date(2029, 3, 1)),
                      user=_as(uid), conn=conn)["lock_extension"]

    assert (ext["exhibits"], ext["extended"], ext["already_held"],
            ext["failed"]) == (1, 1, 0, 0)
    register = exhibit_register(conn, case_id=case_id, clearance="AMBER",
                                compartments=[])
    assert register["total"] == ext["exhibits"], "the count the register gives"
    # Every live exhibit was asked, the hidden ones included.
    assert {k for k, _ in store.calls} == {seen_key, red_key, walled_key}
    assert _extended(conn, red), "the RED exhibit's lock was lengthened too"
    assert conn.execute(
        """SELECT count(*) FROM audit.event WHERE object_id = %s
              AND action = 'EVIDENCE_LOCK_EXTENSION_FAILED'""",
        (walled,)).fetchone()[0] == 1, "the audit log names the refusal"
    again = update_case(case_id, UpdateCaseBody(retention_until=date(2029, 3, 1)),
                        user=_as(uid), conn=conn)["lock_extension"]
    assert (again["exhibits"], again["already_held"], again["failed"]) == (1, 1, 0)


# --- the verifier's round: the lock follows the case from lodging -----------

def _lodge(conn, store, case_id, uid, now):
    from noctornal_api.evidence import EvidenceService
    svc = EvidenceService(conn, store, now=lambda: now)
    res = svc.ingest(case_id=case_id, title="lure.png", media_type="image/png",
                     data=os.urandom(64), acquired_by=uid,
                     acquisition_method="MANUAL_UPLOAD", classification="AMBER")
    day = conn.execute("SELECT retention_until FROM core.evidence WHERE id = %s",
                       (res.evidence_id,)).fetchone()[0]
    [(detail,)] = conn.execute(
        """SELECT detail FROM core.evidence_custody
            WHERE evidence_id = %s AND action = 'ACQUIRED'""",
        (res.evidence_id,)).fetchall()
    return res.evidence_id, day, datetime.fromisoformat(detail["lock_ends_at"])


def test_a_lodging_locks_to_the_case_date_as_far_as_the_horizon(conn, horizon):
    """OP-NIGHTJAR-26's shape: retained to 2028-12-31, an exhibit lodged
    in 2026. The lock now runs to the case's date, not a year; the store
    was asked for exactly that instant, and the ACQUIRED row and the day
    say it. Past the horizon it stops at the horizon; a case already due
    gets the default."""
    import noctornal_api.evidence as evidence
    uid = _user(conn)
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    store = LockStore()

    case_id = _case(conn, uid, retention="2028-12-31")
    ev, day, ends = _lodge(conn, store, case_id, uid, now)
    assert ends == _midnight(date(2028, 12, 31)) and day == date(2028, 12, 31)
    assert store.held[f"{case_id}/" + conn.execute(
        "SELECT encode(sha256, 'hex') FROM core.evidence WHERE id = %s",
        (ev,)).fetchone()[0]] == ends, "the store holds what the record says"

    horizon(timedelta(days=400))
    far = _case(conn, uid, retention="2208-12-31")
    _, day, ends = _lodge(conn, store, far, uid, now)
    assert ends == now + timedelta(days=400) and day == ends.date(), (
        "a mistyped year locks no further than the horizon")

    # A case already due on the lodging clock (the table refuses a case
    # created past its own date, so the clock moves instead).
    after = datetime(2029, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    _, _, ends = _lodge(conn, store, case_id, uid, after)
    assert ends == after + evidence.DEFAULT_RETENTION, "never shorter than the default"


# --- the verifier's round: the horizon ---------------------------------------

def test_the_horizon_stops_an_extension_and_the_report_says_so(conn, horizon):
    """A retention date of 2208 locks every exhibit no further than the
    horizon, says so (`capped`), and records it on the custody row; the
    exhibit's day is the lock's, not the case's. Its lock is not called
    short at once, and is once it has fallen a default lock period behind
    the horizon, so a case retained for decades is asked about again once
    a year rather than every day."""
    from noctornal_api.evidence import DEFAULT_RETENTION, EvidenceService
    from noctornal_api.http.routers.evidence import exhibit_register
    reach = horizon(timedelta(days=400))
    uid = _user(conn)
    case_id = _case(conn, uid, retention="2208-01-01")
    ev, key, end = _exhibit(conn, case_id, uid)
    now = datetime(2026, 9, 24, 12, 0, 0, 250000, tzinfo=timezone.utc)
    store = LockStore(held={key: end})

    report = EvidenceService(conn, store, now=lambda: now).extend_locks(
        case_id, date(2208, 1, 1), uid)

    until = now.replace(microsecond=0) + timedelta(seconds=1) + reach
    assert report["capped"] is True and report["extended"] == 1
    assert report["lock_ends_at"] == until.isoformat(), "whole seconds, rounded up"
    assert store.calls == [(key, until)]
    [(detail,)] = _extended(conn, ev)
    assert detail["capped_at_horizon"] is True
    assert detail["case_retention_until"] == "2208-01-01"
    assert conn.execute("SELECT retention_until FROM core.evidence WHERE id = %s",
                        (ev,)).fetchone()[0] == until.date()
    [row] = exhibit_register(conn, case_id=case_id, clearance="RED",
                             compartments=[], now=now)["items"]
    assert row.lock_ends_at == until and row.lock_short_of_case is False
    later = now + DEFAULT_RETENTION + timedelta(days=1)
    page = exhibit_register(conn, case_id=case_id, clearance="RED",
                            compartments=[], now=later)
    assert page["items"][0].lock_short_of_case is True and page["locks_short"] == 1


def test_where_a_lock_counts_as_short(horizon):
    """`lock_short_before`, the one rule the register, the inspector and
    the pane's count use."""
    from noctornal_api.evidence import DEFAULT_RETENTION, lock_short_before
    reach = horizon(timedelta(days=400))
    now = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
    assert lock_short_before(None, now) is None
    assert lock_short_before(date(2026, 9, 24), now) is None, "the case is due"
    inside = date(2027, 6, 1)
    assert lock_short_before(inside, now) == _midnight(inside), (
        "within the horizon, short means ending before the case's own date")
    beyond = date(2208, 1, 1)
    assert lock_short_before(beyond, now) == now + reach - DEFAULT_RETENTION


# --- the register and the inspector read the newest lock -------------------

def test_the_register_and_the_inspector_state_the_extended_lock(conn, horizon):
    """After an extension the register's chip holds to the NEW instant, not
    the ACQUIRED row's, and the inspector's list (x-inspector-chips) carries
    the same lock fields the card draws from. Before it, both say the lock
    ends short of the case, and the register counts it."""
    from noctornal_api.evidence import EvidenceService
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.http.routers.evidence import exhibit_register
    from noctornal_api.http.routers.read import _element_evidence
    uid = _user(conn)
    case_id = _case(conn, uid)
    ev, key, end = _exhibit(conn, case_id, uid)
    node = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label="lock subject",
        created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                                 evidence_id=ev))

    def listed():
        [item] = _element_evidence(conn, "node_id", node, case_id, "RED", [])
        return item

    before = listed()
    assert before.lock_until == date(2027, 1, 10) and before.lock_ends_at == end
    assert before.lock_lapsed is False and before.legal_hold is False
    assert before.purged_at is None
    assert before.lock_short_of_case is True, "2027-01-10 is before 2027-06-01"
    page = exhibit_register(conn, case_id=case_id, clearance="RED", compartments=[])
    assert page["locks_short"] == 1 and page["items"][0].lock_short_of_case
    assert page["lock_target"] == _midnight(date(2027, 6, 1))

    day = date(2029, 3, 1)
    EvidenceService(conn, LockStore(held={key: end})).extend_locks(case_id, day, uid)
    page = exhibit_register(conn, case_id=case_id, clearance="RED", compartments=[])
    [row] = page["items"]
    assert row.lock_until == day and row.lock_ends_at == _midnight(day)
    assert row.lock_short_of_case is False and page["locks_short"] == 0
    assert page["lock_target"] is None
    after = listed()
    assert after.lock_until == day and after.lock_ends_at == _midnight(day)
    assert after.lock_short_of_case is False


# --- the route -----------------------------------------------------------

def test_patching_the_retention_date_extends_and_reports(conn, horizon, monkeypatch):
    """`PATCH /cases/{id}`: the date commits, the locks follow, and the
    answer says how many were lengthened and how many were not."""
    import noctornal_api.evidence as evidence
    from noctornal_api.http.routers.cases import UpdateCaseBody, update_case
    uid = _user(conn)
    case_id = _case(conn, uid)
    _, key, end = _exhibit(conn, case_id, uid)
    _, bad_key, _ = _exhibit(conn, case_id, uid)
    store = LockStore(held={key: end}, refuse={bad_key})
    monkeypatch.setattr(evidence, "EvidenceStorage", lambda: store)
    user = _as(uid)

    out = update_case(case_id, UpdateCaseBody(retention_until=date(2029, 3, 1)),
                      user=user, conn=conn)
    assert out["retention_until"] == "2029-03-01", "the date stands"
    ext = out["lock_extension"]
    assert (ext["extended"], ext["failed"], ext["exhibits"]) == (1, 1, 2)
    assert ext["capped"] is False

    # Saving the same date again retries what failed, and leaves the rest.
    store.refuse.clear()
    again = update_case(case_id, UpdateCaseBody(retention_until=date(2029, 3, 1)),
                        user=user, conn=conn)["lock_extension"]
    assert (again["extended"], again["already_held"], again["failed"]) == (1, 1, 0)

    # A PATCH that does not touch the date touches no lock.
    title = update_case(case_id, UpdateCaseBody(title="Renamed"), user=user, conn=conn)
    assert title["lock_extension"] is None


def test_the_pane_lengthens_locks_short_of_the_case_as_it_stands(
        conn, horizon, monkeypatch):
    """`POST /cases/{id}/evidence/locks`: the flagship's shape, an exhibit
    locked a year short of a date nobody is extending. Lengthened to the
    case's own date, counted over what the caller sees, with one audit row
    for the act; refused on a case marked for destruction."""
    import noctornal_api.evidence as evidence
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers.evidence import exhibit_register, lengthen_locks
    uid = _user(conn, clearance="AMBER")
    case_id = _case(conn, uid, retention="2028-12-31")
    ev, key, end = _exhibit(conn, case_id, uid, lock_day=date(2027, 9, 23))
    hidden, hidden_key, _ = _exhibit(conn, case_id, uid, classification="RED")
    store = LockStore(held={key: end})
    monkeypatch.setattr(evidence, "EvidenceStorage", lambda: store)
    assert exhibit_register(conn, case_id=case_id, clearance="AMBER",
                            compartments=[])["locks_short"] == 1

    out = lengthen_locks(case_id, user=_as(uid), conn=conn)

    assert out.lock_ends_at == _midnight(date(2028, 12, 31)) and not out.capped
    assert (out.exhibits, out.extended, out.failed) == (1, 1, 0), "the RED one is not counted"
    assert {k for k, _ in store.calls} == {key, hidden_key}, "but it is locked"
    assert exhibit_register(conn, case_id=case_id, clearance="AMBER",
                            compartments=[])["locks_short"] == 0
    [(detail,)] = conn.execute(
        """SELECT detail FROM audit.event
            WHERE case_id = %s AND action = 'CASE_EXHIBIT_LOCKS_LENGTHENED'""",
        (case_id,)).fetchall()
    assert detail["extended"] == 1 and detail["exhibits"] == 1

    purged = _case(conn, uid, retention="2028-12-31", status="PURGED")
    _exhibit(conn, purged, uid)
    with pytest.raises(Problem) as refused:
        lengthen_locks(purged, user=_as(uid), conn=conn)
    assert refused.value.status == 409
    assert exhibit_register(conn, case_id=purged, clearance="RED",
                            compartments=[])["locks_short"] == 0, (
        "nothing is offered on a case marked for destruction")


def test_a_case_with_no_exhibits_never_builds_a_store(conn, monkeypatch):
    import noctornal_api.evidence as evidence
    from noctornal_api.http.routers.cases import _extend_exhibit_locks

    def boom():
        raise AssertionError("no store is needed for a case with no exhibits")
    monkeypatch.setattr(evidence, "EvidenceStorage", boom)
    uid = _user(conn)
    case_id = _case(conn, uid)
    assert _extend_exhibit_locks(conn, case_id, date(2029, 1, 1), uid)["exhibits"] == 0


# --- over HTTP: the verb and the control --------------------------------------

LXH = "lxh-%@noctornal.test"


@pytest.fixture()
def committed():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{LXH}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    with c.transaction():
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN {esub}")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{LXH}'")
    c.close()


def _http_user(conn):
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    uid = PgUserStore(conn).create_user(
        f"lxh-{uuid4().hex[:8]}@noctornal.test", "Lock Tester", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid,
                                                           mfa_satisfied=True)
    return uid, token


def test_over_http_the_control_is_offered_and_gated_on_case_update(
        committed, horizon, monkeypatch):
    """The register offers the control (`may_lock`) to the Lead
    investigator and not to an analyst on the same case, and the route
    answers them the same way: 200 and 403."""
    from fastapi.testclient import TestClient

    import noctornal_api.evidence as evidence
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    conn = committed
    owner, owner_token = _http_user(conn)
    analyst, analyst_token = _http_user(conn)
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Lock HTTP', 'AMBER', %s, 'dev', '2028-12-31',
                   '2027-01-01')""", (case_id, f"OP-LXH-{uuid4().hex[:6]}", owner))
    for uid, role in ((owner, "CASE_OWNER"), (analyst, "ANALYST")):
        conn.execute(
            """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
               VALUES (%s, %s, %s, %s)""", (case_id, uid, role, owner))
    _, key, end = _exhibit(conn, case_id, owner, lock_day=date(2027, 9, 23))
    store = LockStore(held={key: end})
    monkeypatch.setattr(evidence, "EvidenceStorage", lambda: store)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    client = TestClient(app)

    def register(token):
        r = client.get(f"{API}/cases/{case_id}/evidence",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        return r.json()

    mine, theirs = register(owner_token), register(analyst_token)
    assert mine["locks_short"] == theirs["locks_short"] == 1
    assert mine["may_lock"] is True and theirs["may_lock"] is False
    assert mine["items"][0]["lock_short_of_case"] is True

    r = client.post(f"{API}/cases/{case_id}/evidence/locks",
                    headers={"Authorization": f"Bearer {analyst_token}"})
    assert r.status_code == 403, r.text
    assert store.calls == [], "nothing was lengthened for a caller without the verb"
    r = client.post(f"{API}/cases/{case_id}/evidence/locks",
                    headers={"Authorization": f"Bearer {owner_token}"})
    assert r.status_code == 200, r.text
    assert r.json()["extended"] == 1
    assert register(owner_token)["locks_short"] == 0


# --- the store's half, measured -----------------------------------------------

class _FakeClient:
    """A store that says yes and holds nothing: the SeaweedFS shape decision
    64 names. `extend_lock` must not believe it."""

    def __init__(self, held):
        self.held = held

    def list_objects(self, bucket, prefix, include_version):
        class V:
            object_name = prefix
            is_delete_marker = False
            version_id = "v1"
        return [V()]

    def get_object_retention(self, bucket, key, version_id=None):
        return self.held

    def set_object_retention(self, bucket, key, config, version_id=None):
        return None


def test_a_store_that_does_not_hold_the_new_date_is_not_believed():
    from minio.commonconfig import COMPLIANCE
    from minio.retention import Retention

    from noctornal_api.evidence import EvidenceError, EvidenceStorage
    storage = EvidenceStorage.__new__(EvidenceStorage)
    storage._bucket = "b"
    storage._client = _FakeClient(Retention(COMPLIANCE, datetime(2027, 1, 1,
                                                                 tzinfo=timezone.utc)))
    with pytest.raises(EvidenceError, match="does not hold it"):
        storage.extend_lock("k", datetime(2029, 1, 1, tzinfo=timezone.utc))
    done = storage.extend_lock("k", datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert done.extended == 0, "an earlier date is already held"


@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_the_live_store_holds_the_lengthened_lock():
    """Against the real MinIO: a COMPLIANCE lock of seconds is lengthened,
    read back, refused a delete, and left alone when asked for less. Under
    `_itest-lock/` so the live lock test's sweep removes it once it lapses;
    every lock here ends within two minutes."""
    from minio.commonconfig import COMPLIANCE

    from noctornal_api.evidence import EvidenceStorage
    storage = EvidenceStorage()
    key = f"_itest-lock/extend-{uuid4().hex}"
    now = datetime.now(timezone.utc)
    storage.put(key, b"extend me", media_type="application/octet-stream",
                retain_until=now + timedelta(seconds=20))
    until = now + timedelta(seconds=90)
    done = storage.extend_lock(key, until)
    assert done.versions == 1 and done.extended == 1
    assert done.previous is not None and done.previous < until
    held = storage._client.get_object_retention(storage.bucket, key)
    assert held.mode == COMPLIANCE and held.retain_until_date >= until.replace(microsecond=0)
    assert storage.extend_lock(key, now + timedelta(seconds=30)).extended == 0
    result = storage.delete_all_versions(key)
    assert result.versions_locked == 1, "the lengthened lock refuses a delete"
