"""The exhibit register and what it answers (ux07-evidence, 2026-09-23).

Eight findings of the 2026-09-22 review lived in the Evidence pane, and
five of them could not be fixed in the console because the list it read
(`GET /evidence-list?limit=200`) did not carry the facts:

- worm-chip-outlives-lock: the storage lock's end date, and whether it
  has passed.
- no-forward-trace-from-exhibit: what rests on an exhibit, counted by the
  rule the canvas marks "evidenced" by.
- upload-drops-provenance: when and under what authority the material was
  obtained, apart from when the server received it.
- verify-writes-custody-silently: the last check, kept on the card.
- evidence-list-silently-capped: how many exhibits there are, a page at a
  time, and every one of them in the pickers' index.

Plus custody-rows-not-court-legible (a row's own detail, defanged) and,
found while fixing no-exhibit-export-control, the API origin serving
attacker-authored markup that docs/19 says it never serves.

Everything is created inside one transaction that is rolled back, the
idiom `test_custody_actor_name_pg.py` uses, so nothing is committed and no
teardown is needed. No MinIO: exhibits are inserted as rows, and the one
test that ingests through the object store is gated on MINIO_ENDPOINT.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="needs a migrated database")

MINIO = os.environ.get("MINIO_ENDPOINT", "")


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


def _user(conn, *, clearance="RED", name="Reg Analyst", global_roles=()):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, %s, 'x', %s) RETURNING id""",
        (f"reg-{uuid4().hex[:8]}@noctornal.test", name, clearance),
    ).fetchone()[0]
    for role in global_roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def _assign(conn, case_id, uid, role):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, uid, role, uid))


def _who(uid, *, fresh=True):
    from noctornal_api.http.deps import CurrentUser
    return CurrentUser(user_id=uid, session_id=uuid4(),
                       session_mfa_at=(datetime.now(timezone.utc) if fresh
                                       else datetime.now(timezone.utc)
                                       - timedelta(hours=2)))


@pytest.fixture()
def world(conn):
    """A case, a Lead investigator, two entities and a tie."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    uid = _user(conn, global_roles=("CASE_OWNER",))
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Register IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-REG-{uuid4().hex[:6]}", uid))
    _assign(conn, case_id, uid, "CASE_OWNER")
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    n1 = g.create_node(case_id=case_id, node_type="IDENTITY", label="one",
                       created_by=uid, assertion=a)
    n2 = g.create_node(case_id=case_id, node_type="IDENTITY", label="two",
                       created_by=uid, assertion=a)
    edge = g.create_edge(case_id=case_id, edge_type="VOUCHED_FOR",
                         src_node_id=n1, dst_node_id=n2, created_by=uid,
                         assertion=a)
    return case_id, uid, n1, n2, edge


def _exhibit(conn, case_id, uid, *, title="exhibit.png", classification="AMBER",
             acquired_at=None, retention_until=None, hostile=False,
             description=None, source_url=None, media_type="image/png"):
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, description, media_type, byte_size, sha256,
                blake3, storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by, source_url,
                retention_until, is_hostile_markup)
           VALUES (%s, %s, %s, %s, 1024, %s, %s, %s, 'test-bucket',
                   %s::core.tlp, 'MANUAL_UPLOAD', COALESCE(%s, now()), %s, %s,
                   %s, %s)
           RETURNING id""",
        (case_id, title, description, media_type, os.urandom(32), os.urandom(32),
         f"reg/{uuid4().hex}", classification, acquired_at, uid, source_url,
         retention_until, hostile),
    ).fetchone()[0]


def _page(conn, case_id, **kw):
    from noctornal_api.http.routers.evidence import exhibit_register
    kw.setdefault("clearance", "RED")
    kw.setdefault("compartments", [])
    return exhibit_register(conn, case_id=case_id, **kw)


def _carry(conn, case_id, uid, ev, *, node_id=None, edge_id=None):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=node_id, edge_id=edge_id,
        assertion=AssertionInput(basis="THIRD_PARTY_REPORT", created_by=uid,
                                 evidence_id=ev))


def _link(conn, uid, ev, *, node_id=None, edge_id=None):
    conn.execute(
        """INSERT INTO core.evidence_link (evidence_id, node_id, edge_id, created_by)
           VALUES (%s, %s, %s, %s)""", (ev, node_id, edge_id, uid))


# --- evidence-list-silently-capped ---------------------------------------

def test_the_register_pages_and_says_how_many_there_are(conn, world):
    """The pane kept the newest 200 without a word; the register says how
    many exist and pages through all of them, newest acquisition first."""
    case_id, uid, *_ = world
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ids = [_exhibit(conn, case_id, uid, title=f"ex-{i:02d}.png",
                    acquired_at=base + timedelta(days=i)) for i in range(7)]
    first = _page(conn, case_id, limit=3)
    assert (first["total"], first["matching"]) == (7, 7)
    assert [x.title for x in first["items"]] == ["ex-06.png", "ex-05.png", "ex-04.png"]
    last = _page(conn, case_id, limit=3, offset=6)
    assert [x.id for x in last["items"]] == [str(ids[0])], (
        "the earliest exhibit, the original seizure, must be reachable")


def test_the_register_filters_by_words_one_exhibit_and_the_reader_ceiling(conn, world):
    case_id, uid, *_ = world
    _exhibit(conn, case_id, uid, title="seized-phone.bin",
             description="Extraction of the courier's handset")
    other = _exhibit(conn, case_id, uid, title="ledger.pdf")
    _exhibit(conn, case_id, uid, title="red-report.pdf", classification="RED")
    by_title = _page(conn, case_id, q="phone")
    assert [x.title for x in by_title["items"]] == ["seized-phone.bin"]
    assert _page(conn, case_id, q="courier")["matching"] == 1, "description too"
    assert _page(conn, case_id, q="100%")["matching"] == 0, "a % is literal"
    one = _page(conn, case_id, evidence_id=other)
    assert [x.id for x in one["items"]] == [str(other)] and one["total"] == 3
    amber = _page(conn, case_id, clearance="AMBER")
    assert amber["total"] == 2, "an exhibit above the reader's clearance is not counted"
    assert "red-report.pdf" not in [x.title for x in amber["items"]]


def test_the_index_carries_every_exhibit_and_the_total(conn, world):
    """The attach pickers read this, not the pane's page."""
    from noctornal_api.http.routers import evidence as route
    case_id, uid, *_ = world
    for i in range(3):
        _exhibit(conn, case_id, uid, title=f"i-{i}.png")
    _exhibit(conn, case_id, uid, title="red.png", classification="RED")
    reader = _user(conn, clearance="AMBER", global_roles=("ANALYST",))
    _assign(conn, case_id, reader, "ANALYST")
    out = route.index(case_id, user=_who(reader), conn=conn)
    assert out.total == 3 and len(out.items) == 3
    assert "red.png" not in [x.title for x in out.items]


# --- no-forward-trace-from-exhibit ---------------------------------------

def test_backs_counts_both_routes_and_only_what_the_canvas_draws(conn, world):
    """"What rests on this exhibit" by the projection's own rule: a live
    assertion or a link, on an element that is live, not deleted, not
    merged away and visible to the reader."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.http.routers import evidence as route
    case_id, uid, n1, n2, edge = world
    ev = _exhibit(conn, case_id, uid, title="load-bearing.png")
    idle = _exhibit(conn, case_id, uid, title="unused.png")
    _link(conn, uid, ev, node_id=n1)
    _carry(conn, case_id, uid, ev, edge_id=edge)
    _carry(conn, case_id, uid, ev, node_id=n1)          # both routes, one entity
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    gone = g.create_node(case_id=case_id, node_type="IDENTITY", label="gone",
                         created_by=uid, assertion=a)
    merged = g.create_node(case_id=case_id, node_type="IDENTITY", label="merged",
                           created_by=uid, assertion=a)
    red = g.create_node(case_id=case_id, node_type="IDENTITY", label="red",
                        created_by=uid, assertion=a, classification="RED")
    withdrawn = g.create_node(case_id=case_id, node_type="IDENTITY",
                              label="withdrawn", created_by=uid, assertion=a)
    for target in (gone, merged, red):
        _link(conn, uid, ev, node_id=target)
    claim = _carry(conn, case_id, uid, ev, node_id=withdrawn)
    g.retract_assertion(claim, retracted_by=uid, reason="burned",
                        at=datetime.now(timezone.utc))
    conn.execute("UPDATE core.node SET deleted_at = now() WHERE id = %s", (gone,))
    conn.execute("UPDATE core.node SET merged_into_id = %s WHERE id = %s",
                 (n2, merged))

    rows = {x.title: x for x in _page(conn, case_id)["items"]}
    assert (rows["load-bearing.png"].backs_nodes, rows["load-bearing.png"].backs_edges) == (2, 1), (
        "one, red and the tie; not the deleted, merged or withdrawn ones")
    assert (rows["unused.png"].backs_nodes, rows["unused.png"].backs_edges) == (0, 0)
    amber = {x.title: x for x in _page(conn, case_id, clearance="AMBER")["items"]}
    assert amber["load-bearing.png"].backs_nodes == 1, "the RED entity is not counted"

    page = _page(conn, case_id, backs_nothing=True)
    assert [x.id for x in page["items"]] == [str(idle)]
    assert page["backs_nothing"] == 1 and page["total"] == 2

    out = route.backs(case_id, ev, user=_who(uid), conn=conn)
    assert (out.nodes, out.edges, out.truncated) == (2, 1, False)
    by_id = {x.id: x for x in out.items}
    assert sorted(by_id[str(n1)].via) == ["ASSERTION", "LINK"]
    assert by_id[str(red)].via == ["LINK"]
    tie = by_id[str(edge)]
    assert (tie.kind, tie.src_label, tie.dst_label, tie.via) == (
        "edge", "one", "two", ["ASSERTION"])


def test_a_purged_exhibit_backs_nothing_as_the_canvas_draws_it(conn, world):
    """The projection's rule has a purge leg (`evidenced_sql`: purged_at IS
    NULL). The register missed it, so a purged exhibit's card said "Backs 1
    entity" while the canvas drew that entity hollow, and the "backs
    nothing" count left it out (verifier, 2026-09-23)."""
    from noctornal_api.http.routers import evidence as route
    from noctornal_api.projections import evidenced_sql
    case_id, uid, n1, _n2, edge = world
    ev = _exhibit(conn, case_id, uid, title="destroyed.png")
    _link(conn, uid, ev, node_id=n1)
    _carry(conn, case_id, uid, ev, edge_id=edge)
    assert _page(conn, case_id)["items"][0].backs_nodes == 1
    conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (ev,))

    [row] = _page(conn, case_id)["items"]
    assert (row.backs_nodes, row.backs_edges) == (0, 0)
    drawn = conn.execute(
        f"SELECT {evidenced_sql('node_id', 'n')} FROM core.node n WHERE n.id = %s",
        ("RED", [], n1)).fetchone()[0]
    assert drawn is False, "and the canvas agrees: the entity is hollow"
    page = _page(conn, case_id, backs_nothing=True)
    assert page["backs_nothing"] == 1 and [x.id for x in page["items"]] == [str(ev)]
    out = route.backs(case_id, ev, user=_who(uid), conn=conn)
    assert (out.nodes, out.edges, out.items) == (0, 0, [])


# --- worm-chip-outlives-lock ---------------------------------------------

def _at(y, m, d, hh=0, mm=0, ss=0):
    return datetime(y, m, d, hh, mm, ss, tzinfo=timezone.utc)


def test_the_lock_date_travels_and_says_when_it_has_passed(conn, world):
    """An exhibit lodged before the lock's instant was recorded carries
    only the day, and its lock is not counted on from the start of that
    day: the store's lock ends part way through it (verifier, 2026-09-23:
    "held through its last day" was the overstatement)."""
    case_id, uid, *_ = world
    _exhibit(conn, case_id, uid, title="old.png", retention_until=date(2026, 1, 5))
    _exhibit(conn, case_id, uid, title="new.png", retention_until=date(2027, 9, 17))
    _exhibit(conn, case_id, uid, title="undated.png")
    rows = {x.title: x for x in _page(conn, case_id, now=_at(2026, 9, 23, 12))["items"]}
    assert (rows["old.png"].lock_until, rows["old.png"].lock_lapsed) == (date(2026, 1, 5), True)
    assert (rows["new.png"].lock_until, rows["new.png"].lock_lapsed) == (date(2027, 9, 17), False)
    assert rows["new.png"].lock_ends_at is None, "the day only: no instant invented"
    assert (rows["undated.png"].lock_until, rows["undated.png"].lock_lapsed) == (None, False)
    eve = {x.title: x for x in _page(conn, case_id, now=_at(2027, 9, 16, 23, 59, 59))["items"]}
    assert eve["new.png"].lock_lapsed is False
    on_the_day = {x.title: x for x in _page(conn, case_id, now=_at(2027, 9, 17, 0, 0, 1))["items"]}
    assert on_the_day["new.png"].lock_lapsed is True, (
        "the time of day is unknown, so the lock is not counted on that day")


def test_a_recorded_lock_instant_is_the_one_the_store_holds_to(conn, world):
    """Since 2026-09-23 the ACQUIRED row carries the lock's exact end; the
    register reads the lock as held until that instant and no longer."""
    from noctornal_api.evidence import EvidenceService
    case_id, uid, *_ = world
    ev = _exhibit(conn, case_id, uid, title="timed.png", retention_until=date(2027, 9, 24))
    ends = _at(2027, 9, 24, 3, 2, 3)
    EvidenceService(conn, storage=None)._custody(
        ev, "ACQUIRED", uid, hash_verified=True,
        detail={"acquisition_method": "MANUAL_UPLOAD", "acquired_at_stated": False,
                "lock_ends_at": ends.isoformat()})
    before = _page(conn, case_id, now=ends - timedelta(seconds=1))["items"][0]
    assert (before.lock_ends_at, before.lock_lapsed) == (ends, False), (
        "held that morning, where the day alone would already stop counting")
    after = _page(conn, case_id, now=ends)["items"][0]
    assert after.lock_lapsed is True, "not a second past the store's own lock"


def test_a_lock_instant_that_is_not_this_lock_falls_back_to_the_day():
    from noctornal_api.http.routers.evidence import lock_state
    day = date(2027, 9, 24)
    assert lock_state(day, {"lock_ends_at": "2027-09-25T01:00:00+00:00"},
                      _at(2027, 9, 24, 0, 30)) == (None, True)
    assert lock_state(day, {"lock_ends_at": "not a time"},
                      _at(2027, 9, 23, 23)) == (None, False)
    naive = lock_state(day, {"lock_ends_at": "2027-09-24T03:02:03"}, _at(2027, 9, 24, 3))
    assert naive == (_at(2027, 9, 24, 3, 2, 3), False), "a stamp with no offset is UTC"
    assert lock_state(None, {"lock_ends_at": "2027-09-24T03:02:03"}, _at(2030, 1, 1)) == (
        None, False)


def test_the_policy_names_the_lock_period_and_that_an_extension_lengthens_it():
    """x-lock-extension (2026-09-24): the lock runs to the case's retention
    date from lodging and an extension lengthens it, so the policy no
    longer says the lock ignores that date. The verifier's round: it names
    the horizon a lock is set within, and that nobody can shorten one."""
    from noctornal_api.evidence import DEFAULT_RETENTION, LOCK_HORIZON
    from noctornal_api.http.routers.evidence import size_policy
    out = size_policy(uuid4(), user=None)
    assert out["lock_days"] == DEFAULT_RETENTION.days
    assert out["lock_follows_case_retention"] is True
    assert out["lock_horizon_days"] == LOCK_HORIZON.days
    assert "runs to the case's retention date" in out["notice"]
    assert "from the moment it is lodged" in out["notice"]
    assert "Extending the date lengthens it" in out["notice"]
    assert "nobody can shorten it" in out["notice"]
    assert "from acquisition" not in out["notice"], (
        "the lock runs from lodging; 'acquired' is the stated time")
    assert "retention period" not in out["notice"]


# --- upload-drops-provenance ---------------------------------------------

def test_provenance_is_checked_before_a_byte_is_stored():
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers.evidence import _provenance
    now = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
    got = _provenance("LEGAL", "  a phone  ", " locker 4 ", "2026-09-17T15:18:00",
                      "PO-2026-114", now=now)
    assert got == {"description": "a phone", "source_url": "locker 4",
                   "authority_ref": "PO-2026-114",
                   "acquired_at": datetime(2026, 9, 17, 15, 18, tzinfo=timezone.utc)}, (
        "a time with no offset is UTC")
    assert _provenance("MANUAL_UPLOAD", "", "", "", None, now=now)["acquired_at"] is None
    offset = _provenance("MANUAL_UPLOAD", None, None, "2026-09-17T12:18:00-03:00",
                         None, now=now)["acquired_at"]
    assert offset == datetime(2026, 9, 17, 15, 18, tzinfo=timezone.utc)
    for bad in (("LEGAL", None, None, None, "  "),                 # no authority
                ("MANUAL_UPLOAD", None, None, "2026-09-24T12:00:00Z", None),
                ("MANUAL_UPLOAD", None, None, "last tuesday", None),
                ("MANUAL_UPLOAD", "x" * 4001, None, None, None)):
        with pytest.raises(Problem) as err:
            _provenance(*bad, now=now)
        assert err.value.status == 400


def test_the_register_shows_stated_provenance_defanged(conn, world):
    """What the ACQUIRED row says (stated time, authority) and the typed
    source and description, as defanged runs and never raw."""
    from noctornal_api.evidence import EvidenceService
    case_id, uid, *_ = world
    ev = _exhibit(conn, case_id, uid, title="kit.html",
                  source_url="https://evil.example/login",
                  description="Kit captured from https://evil.example/login")
    EvidenceService(conn, storage=None)._custody(
        ev, "ACQUIRED", uid, hash_verified=True,
        detail={"acquisition_method": "LEGAL", "acquired_at_stated": True,
                "authority_ref": "PO-2026-114"})
    [row] = _page(conn, case_id)["items"]
    assert row.acquired_at_stated is True
    assert "".join(r["text"] for r in row.authority_segments) == "PO-2026-114"
    source = "".join(r["text"] for r in row.source_segments)
    assert "evil.example" not in source and "hxxps" in source
    assert "evil.example" not in "".join(r["text"] for r in row.description_segments)
    assert row.lodged_at is not None and row.acquired_by_name == "Reg Analyst"


def test_an_exhibit_lodged_before_the_flag_keeps_its_stated_time(conn, world):
    """The `acquired_at_stated` flag exists on ACQUIRED rows written since
    2026-09-23. An earlier exhibit ingested with a real acquisition time
    (the README showcase seeds them thirty days back) has none, and read
    "acquired at lodging, no earlier time stated", hiding the time its
    record holds (verifier, 2026-09-23)."""
    from noctornal_api.evidence import EvidenceService
    case_id, uid, *_ = world
    svc = EvidenceService(conn, storage=None)
    seeded = _exhibit(conn, case_id, uid, title="seeded.png",
                      acquired_at=datetime.now(timezone.utc) - timedelta(days=30))
    svc._custody(seeded, "ACQUIRED", uid, hash_verified=True,
                 detail={"sha256": "00", "bytes": 1024})       # the old shape
    _exhibit(conn, case_id, uid, title="defaulted.png")          # no row at all
    _exhibit(conn, case_id, uid, title="skewed.png",
             acquired_at=datetime.now(timezone.utc) - timedelta(minutes=2))
    flagged = _exhibit(conn, case_id, uid, title="flagged.png",
                       acquired_at=datetime.now(timezone.utc) - timedelta(days=3))
    svc._custody(flagged, "ACQUIRED", uid, hash_verified=True,
                 detail={"acquired_at_stated": False})
    rows = {x.title: x.acquired_at_stated for x in _page(conn, case_id)["items"]}
    assert rows["seeded.png"] is True, "a time a month before lodging was stated"
    assert rows["defaulted.png"] is False, "a time on the lodging instant was not"
    assert rows["skewed.png"] is False, "inside the clock-skew margin it is not claimed"
    assert rows["flagged.png"] is False, "where the row says, the row wins"


# --- verify-writes-custody-silently --------------------------------------

def test_the_last_check_stays_on_the_card(conn, world):
    from noctornal_api.evidence import EvidenceService
    case_id, uid, *_ = world
    ev = _exhibit(conn, case_id, uid)
    assert _page(conn, case_id)["items"][0].last_check is None
    svc = EvidenceService(conn, storage=None)
    svc._custody(ev, "HASH_VERIFIED", uid, hash_verified=True)
    svc._custody(ev, "HASH_VERIFIED", uid, hash_verified=False)
    check = _page(conn, case_id)["items"][0].last_check
    assert check.ok is False and check.by_name == "Reg Analyst", (
        "the newest check, a mismatch, is the one kept")


# --- custody-rows-not-court-legible --------------------------------------

def test_the_custody_route_returns_the_row_detail_defanged(conn, world):
    from noctornal_api.evidence import EvidenceService
    from noctornal_api.http.routers import evidence as route
    case_id, uid, *_ = world
    ev = _exhibit(conn, case_id, uid)
    svc = EvidenceService(conn, storage=None)
    svc._custody(ev, "ACQUIRED", uid, hash_verified=True,
                 detail={"sha256": "ab", "bytes": 1024,
                         "acquisition_method": "MANUAL_UPLOAD",
                         "lock_ends_at": "2027-09-24T03:02:03+00:00"})
    svc._custody(ev, "ACQUIRED", uid,
                 detail={"sha256": "ab", "deduplicated": True,
                         "acquisition_method": "LEGAL",
                         "source_url": "https://evil.example/x",
                         "authority_ref": "PO-9", "secret": "never"})
    first, again = route.custody(case_id, ev, user=_who(uid), conn=conn)
    assert first.detail == {"bytes": 1024, "acquisition_method": "MANUAL_UPLOAD",
                            "lock_ends_at": "2027-09-24T03:02:03+00:00"}, (
        "the lock's end is part of the record that goes to court")
    assert again.detail["deduplicated"] is True, (
        "a re-acquisition must not read like the original")
    assert "secret" not in again.detail and "source_url" not in again.detail
    assert "hxxps" in "".join(r["text"] for r in again.detail["source_segments"])
    assert again.detail["authority_segments"][0]["text"] == "PO-9"


# --- hostile markup is not served from the application origin ---------

def test_attacker_markup_is_refused_on_content_and_export_and_audited(conn, world, monkeypatch):
    """docs/19 section 1.1: "The API origin never serves those bytes." Both
    routes served them until 2026-09-23. The refusal comes after the gate
    and before the store is touched (storage=None would raise)."""
    from noctornal_api.evidence import EvidenceService
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers import evidence as route
    case_id, uid, *_ = world
    ev = _exhibit(conn, case_id, uid, title="lure.eml", hostile=True,
                  media_type="message/rfc822")
    monkeypatch.setattr(route, "_svc", lambda c: EvidenceService(c, storage=None))
    for call in (lambda: route.download(case_id, ev, user=_who(uid), conn=conn),
                 lambda: route.export(case_id, ev, user=_who(uid), conn=conn)):
        with pytest.raises(Problem) as err:
            call()
        assert err.value.status == 409 and "attacker-authored" in err.value.detail
    purposes = [r[0] for r in conn.execute(
        """SELECT detail->>'purpose' FROM audit.event
            WHERE object_id = %s AND action = 'EVIDENCE_EGRESS_REFUSED'
            ORDER BY seq""", (ev,))]
    assert purposes == ["content", "export"]


# --- no-exhibit-export-control: the step-up is said as a step-up --------

def test_a_stale_sign_in_is_told_to_sign_in_not_that_it_lacks_the_permission(conn, world):
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers import evidence as route
    case_id, uid, *_ = world
    ev = _exhibit(conn, case_id, uid)
    route._authorize_export(conn, _who(uid), case_id, ev)       # fresh: allowed
    with pytest.raises(Problem) as stale:
        route._authorize_export(conn, _who(uid, fresh=False), case_id, ev)
    assert stale.value.status == 403 and stale.value.detail == route.STEP_UP_DETAIL
    analyst = _user(conn, global_roles=("ANALYST",))
    _assign(conn, case_id, analyst, "ANALYST")
    with pytest.raises(Problem) as role:
        route._authorize_export(conn, _who(analyst), case_id, ev)
    assert "missing permission evidence.export" in role.value.detail, (
        "a role a sign-in would not fix is not sent round the sign-in")


def test_the_register_says_which_controls_the_reader_holds(conn, world):
    from noctornal_api.http.routers import evidence as route
    case_id, uid, *_ = world
    _exhibit(conn, case_id, uid)
    lead = route.register(case_id, offset=0, limit=50, q=None, backs_nothing=False,
                          evidence_id=None, user=_who(uid, fresh=False), conn=conn)
    assert lead.may_export is True, "offered even when the sign-in has aged"
    assert lead.may_audit is False
    analyst = _user(conn, global_roles=("ANALYST",))
    _assign(conn, case_id, analyst, "ANALYST")
    other = route.register(case_id, offset=0, limit=50, q=None, backs_nothing=False,
                           evidence_id=None, user=_who(analyst), conn=conn)
    assert other.may_export is False and other.total == 1


# --- the ingest records provenance on the custody row (needs MinIO) -----

@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_ingest_records_the_stated_time_and_authority(conn, world):
    from noctornal_api.evidence import EvidenceService, EvidenceStorage
    case_id, uid, *_ = world
    svc = EvidenceService(conn, EvidenceStorage())
    when = datetime(2026, 9, 1, 9, 30, tzinfo=timezone.utc)
    data = b"seized-" + uuid4().hex.encode()
    res = svc.ingest(case_id=case_id, title="phone.bin", media_type="application/octet-stream",
                     data=data, acquired_by=uid, acquisition_method="LEGAL",
                     acquired_at=when, authority_ref="PO-2026-114",
                     source_url="Evidence locker 4",
                     retain_until=datetime.now(timezone.utc) + timedelta(seconds=30))
    row = conn.execute("SELECT acquired_at, created_at FROM core.evidence WHERE id = %s",
                       (res.evidence_id,)).fetchone()
    assert row[0] == when and row[1] > when, "acquired and lodged are apart"
    [acquired] = svc.custody_log(res.evidence_id)
    assert acquired.detail["authority_ref"] == "PO-2026-114"
    assert acquired.detail["acquired_at_stated"] is True
    # The lock's exact end, the instant handed to the store, and the one
    # the register holds the chip to (worm-chip-outlives-lock, verifier).
    ends = datetime.fromisoformat(acquired.detail["lock_ends_at"])
    [row] = _page(conn, case_id)["items"]
    assert row.lock_ends_at == ends and row.lock_until == ends.date()
    assert row.lock_lapsed is False
    assert _page(conn, case_id, now=ends)["items"][0].lock_lapsed is True
    svc.ingest(case_id=case_id, title="phone again", media_type="application/octet-stream",
               data=data, acquired_by=uid, acquisition_method="COLLECTOR")
    again = svc.custody_log(res.evidence_id)[-1]
    assert again.detail["deduplicated"] is True
    assert "lock_ends_at" not in again.detail, "a re-acquisition locks nothing"
    assert again.detail["acquired_at_stated"] is False
    assert again.detail["acquisition_method"] == "COLLECTOR"
