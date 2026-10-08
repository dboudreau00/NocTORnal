"""The ledgers' tail anchor, and the caveat beside every green tick
(evidence-chain-no-anchor, 2026-10-03).

Every check in the two verifiers is relative: a row is accused because
another row disagrees with it. Nothing names the newest row as a predecessor,
so rows deleted from the END leave nothing behind to disagree, and a run of
rows edited and then re-chained with fresh hashes (plain SHA-256, the
expression is in the repo) is self-consistent. `/audit/custody/verify` said
so and returned `tail_row_hash`; `/audit/verify` said "intact" with neither
the sentence nor the hash.

What these tests hold:

- THE TAIL: both reports carry the newest row of the WHOLE ledger and the
  row count, windowed or not;
- THE ANCHOR: handed back, the recorded row must still be here at its
  number with its hash. A tail deleted since is ANCHOR_MISSING, an edit
  re-chained to the tail is ANCHOR_REWRITTEN, a renumbering is ANCHOR_MOVED,
  and each makes `intact` false. WITHOUT the anchor the same tampering still
  reads intact, which is the documented blind spot, and the test says so;
- THE ANSWER: `/audit/verify` carries the caveat on EVERY run, names the
  anchor parameters, and says what a held anchor does and does not cover;
  the custody answer carries the same pair. Half an anchor is a 422.

All tampering is inside a transaction that is rolled back.
"""
from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from rolled_back import empty_ledgers

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs a migrated database")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "g49n-%@noctornal.test"
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture()
def tamperable():
    """A transaction that is rolled back, with both ledgers emptied inside it:
    the walk meets only what the test writes, whatever another suite left."""
    from noctornal_api.db import dsn
    conn = psycopg.connect(dsn())
    try:
        empty_ledgers(conn)
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _seed(conn, n: int = 6) -> int:
    start = conn.execute("SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]
    for i in range(n):
        conn.execute(
            "INSERT INTO audit.event (actor_kind, action, outcome, detail) "
            "VALUES ('USER', %s, 'SUCCESS', '{}'::jsonb)", (f"G49_ANCHOR_{i}",))
    return start


def _tail(conn) -> tuple[int, str]:
    seq, digest = conn.execute(
        "SELECT seq, encode(row_hash, 'hex') FROM audit.event "
        "ORDER BY seq DESC LIMIT 1").fetchone()
    return seq, digest


# ---------------------------------------------------------------------------
# audit.event
# ---------------------------------------------------------------------------

def test_the_report_carries_the_tail_to_record(tamperable):
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable)
    seq, digest = _tail(tamperable)
    report = verify_chain(tamperable, since_seq=since)
    assert (report.tail_seq, report.tail_row_hash) == (seq, digest)
    assert report.total_rows == tamperable.execute(
        "SELECT count(*) FROM audit.event").fetchone()[0]
    windowed = verify_chain(tamperable, limit=2)
    assert (windowed.tail_seq, windowed.tail_row_hash) == (seq, digest), \
        "the tail is the whole log's, windowed or not"


def test_a_held_anchor_is_held_and_counts_the_rows_since(tamperable):
    from noctornal_api.audit_verify import ChainAnchor, verify_chain

    _seed(tamperable)
    seq, digest = _tail(tamperable)
    _seed(tamperable, n=3)
    report = verify_chain(tamperable, limit=1, anchor=ChainAnchor(seq, digest))
    assert report.anchor.status == "HELD"
    assert report.anchor.rows_since == 3
    assert report.intact


def test_a_deleted_tail_is_invisible_without_an_anchor_and_a_break_with_one(tamperable):
    """The cheapest delete there is: one statement, no hashing. The relative
    checks answer intact; the anchor is the only thing that says otherwise."""
    from noctornal_api.audit_verify import ChainAnchor, verify_chain

    since = _seed(tamperable)
    seq, digest = _tail(tamperable)
    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        "DELETE FROM audit.event WHERE seq IN "
        "(SELECT seq FROM audit.event ORDER BY seq DESC LIMIT 2)")

    blind = verify_chain(tamperable, since_seq=since)
    assert blind.intact, "the tail deletion became visible without an anchor"
    assert blind.tail_row_hash != digest, "the tail moved, which is what to record"

    anchored = verify_chain(tamperable, since_seq=since, anchor=ChainAnchor(seq, digest))
    assert not anchored.intact
    assert [b.kind for b in anchored.breaks] == ["ANCHOR_MISSING"]
    assert anchored.anchor.status == "MISSING"


def test_an_edit_re_chained_to_the_tail_is_invisible_without_an_anchor(tamperable):
    """Edit row k and recompute every later hash. The result is
    self-consistent, so every relative check passes; the recorded hash of the
    tail no longer exists."""
    from noctornal_api.audit_verify import _HASH_EXPR, ChainAnchor, verify_chain

    since = _seed(tamperable)
    seq, digest = _tail(tamperable)
    first = tamperable.execute(
        "SELECT min(seq) FROM audit.event WHERE seq > %s", (since,)).fetchone()[0]
    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        "UPDATE audit.event SET action = 'G49_NOTHING_HAPPENED' WHERE seq = %s",
        (first,))
    previous = None
    for (row_seq,) in tamperable.execute(
            "SELECT seq FROM audit.event WHERE seq >= %s ORDER BY seq",
            (first,)).fetchall():
        if previous is not None:
            tamperable.execute(
                "UPDATE audit.event SET prev_hash = %s WHERE seq = %s",
                (previous, row_seq))
        previous = tamperable.execute(
            f"UPDATE audit.event AS e SET row_hash = {_HASH_EXPR} "
            "WHERE e.seq = %s RETURNING e.row_hash", (row_seq,)).fetchone()[0]
    # The first edited row's own predecessor is untouched; everything after
    # it was recomputed.
    blind = verify_chain(tamperable, since_seq=since)
    assert blind.intact, [b.kind for b in blind.breaks]

    anchored = verify_chain(tamperable, since_seq=since, anchor=ChainAnchor(seq, digest))
    assert not anchored.intact
    assert anchored.anchor.status == "REWRITTEN"
    assert [b.kind for b in anchored.breaks] == ["ANCHOR_REWRITTEN"]


def test_a_renumbering_is_a_break_with_an_anchor(tamperable):
    from noctornal_api.audit_verify import ChainAnchor, verify_chain

    since = _seed(tamperable)
    seq, digest = _tail(tamperable)
    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute("UPDATE audit.event SET seq = %s WHERE seq = %s",
                       (seq + 1_000_000, seq))
    report = verify_chain(tamperable, since_seq=since, anchor=ChainAnchor(seq, digest))
    assert report.anchor.status == "MOVED"
    assert report.anchor.found_seq == seq + 1_000_000
    assert not report.intact


def test_an_anchor_is_a_position_and_a_sha256():
    from noctornal_api.audit_verify import ChainAnchor
    from noctornal_api.custody_verify import CustodyAnchor

    for bad in ("", "abc", "G" * 64, "A" * 64, "0" * 63):
        with pytest.raises(ValueError):
            ChainAnchor(1, bad)
        with pytest.raises(ValueError):
            CustodyAnchor(1, bad)
    assert ChainAnchor(1, "0" * 64).seq == 1


# ---------------------------------------------------------------------------
# core.evidence_custody
# ---------------------------------------------------------------------------

def _custody(conn, n: int = 4):
    """A user, a case, an exhibit and `n` custody rows, inside the open
    transaction; the ids and the exhibit."""
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'Anchor', 'x', 'RED') RETURNING id""",
        (f"g49n-{uuid4().hex[:8]}@noctornal.test",)).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Anchor IT', 'AMBER', %s, 'dev', '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-G49-{uuid4().hex[:6]}", uid))
    ev = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification, acquisition_method,
                acquired_at, acquired_by)
           VALUES (%s, 'anchor', 'image/png', 1, %s, %s, %s, 'b', 'AMBER',
                   'SCREENSHOT', now(), %s) RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"g49/{uuid4().hex}", uid)
    ).fetchone()[0]
    ids = [conn.execute(
        "INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
        "VALUES (%s, 'VIEWED', %s) RETURNING id", (ev, uid)).fetchone()[0]
        for _ in range(n)]
    return ev, ids


def test_the_custody_report_carries_the_tail_and_honours_an_anchor(tamperable):
    from noctornal_api.custody_verify import CustodyAnchor, verify_custody_chain

    ev, ids = _custody(tamperable)
    digest = tamperable.execute(
        "SELECT encode(row_hash, 'hex') FROM core.evidence_custody WHERE id = %s",
        (ids[-1],)).fetchone()[0]
    report = verify_custody_chain(tamperable, evidence_id=ev,
                                  anchor=CustodyAnchor(ids[-1], digest))
    assert (report.tail_id, report.tail_row_hash) == (ids[-1], digest), \
        "the tail is whole-ledger even on a scoped run"
    assert report.total_rows >= len(ids)
    assert report.anchor.status == "HELD" and report.anchor.rows_since == 0

    tamperable.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
    tamperable.execute("DELETE FROM core.evidence_custody WHERE id >= %s", (ids[-2],))
    blind = verify_custody_chain(tamperable)
    assert blind.intact, "the deleted tail is the documented blind spot"
    anchored = verify_custody_chain(tamperable, anchor=CustodyAnchor(ids[-1], digest))
    assert not anchored.intact
    assert [b.kind for b in anchored.breaks] == ["ANCHOR_MISSING"]


# ---------------------------------------------------------------------------
# The endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


@pytest.fixture
def officer(conn):
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore

    email = f"g49n-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Officer", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'SECURITY_OFFICER')", (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def test_verify_says_what_it_cannot_see_on_every_run_and_returns_the_tail(
        client, officer):
    body = client.get("/api/v1/audit/verify", headers=officer).json()
    assert body["windowed"] is False
    assert body["caveat"], "an unwindowed answer had no caveat"
    for word in ("END", "re-chained", "tail_seq", "tail_row_hash",
                 "anchor_seq", "anchor_hash"):
        assert word in body["caveat"], (word, body["caveat"])
    assert body["tail_seq"] and len(body["tail_row_hash"]) == 64
    assert body["rows_in_log"] >= 1
    assert body["anchor"] is None
    assert body["fork_boundary_seq"] is not None

    windowed = client.get("/api/v1/audit/verify", headers=officer,
                          params={"limit": 5}).json()
    assert windowed["windowed"] is True
    assert "OUTSIDE" in windowed["caveat"] and "tail_row_hash" in windowed["caveat"]
    assert windowed["tail_row_hash"], "the tail is reported on a windowed run too"


def test_verify_compares_an_anchor_you_hand_back(client, officer, conn):
    first = client.get("/api/v1/audit/verify", headers=officer).json()
    anchor = {"anchor_seq": first["tail_seq"], "anchor_hash": first["tail_row_hash"]}
    held = client.get("/api/v1/audit/verify", headers=officer, params=anchor).json()
    assert held["anchor"]["held"] is True and held["anchor"]["status"] == "HELD"
    assert held["anchor"]["rows_since"] >= 0
    assert "not covered" in held["anchor"]["note"]

    wrong = client.get("/api/v1/audit/verify", headers=officer,
                       params={"anchor_seq": first["tail_seq"],
                               "anchor_hash": "0" * 64}).json()
    assert wrong["anchor"]["held"] is False
    assert wrong["anchor"]["status"] == "REWRITTEN"
    assert wrong["intact"] is False
    assert [b["kind"] for b in wrong["breaks"]] == ["ANCHOR_REWRITTEN"]

    gone = client.get("/api/v1/audit/verify", headers=officer,
                      params={"anchor_seq": first["tail_seq"] + 10 ** 12,
                              "anchor_hash": "1" * 64}).json()
    assert gone["anchor"]["status"] == "MISSING"
    assert gone["intact"] is False


def test_half_an_anchor_or_a_malformed_one_is_a_422(client, officer):
    url = "/api/v1/audit/verify"
    assert client.get(url, headers=officer, params={"anchor_seq": 5}).status_code == 422
    assert client.get(url, headers=officer,
                      params={"anchor_hash": "0" * 64}).status_code == 422
    for bad in ("zz", "A" * 64, "0" * 63):
        assert client.get(url, headers=officer, params={
            "anchor_seq": 5, "anchor_hash": bad}).status_code == 422, bad
    custody = "/api/v1/audit/custody/verify"
    assert client.get(custody, headers=officer, params={"anchor_id": 5}).status_code == 422
    assert client.get(custody, headers=officer, params={
        "anchor_hash": "0" * 64}).status_code == 422


def test_the_custody_answer_carries_the_same_pair(tamperable):
    """The route function itself, on the transaction that holds the custody
    rows it needs (it used to ask the API and skip when the database held
    none)."""
    from noctornal_api.http.routers.audit import verify_custody

    _custody(tamperable)

    def ask(**anchor):
        return verify_custody(
            evidence_id=None, anchor_id=anchor.get("anchor_id"),
            anchor_hash=anchor.get("anchor_hash"), user=None,
            conn=tamperable, chain=tamperable)

    first = ask()
    assert first["caveat"] and "END" in first["caveat"]
    assert "anchor_id" in first["caveat"] and "anchor_hash" in first["caveat"]
    assert first["rows_in_ledger"] == 4 and first["tail_row_hash"]
    held = ask(anchor_id=first["tail_id"], anchor_hash=first["tail_row_hash"])
    assert held["anchor"]["held"] is True
    missing = ask(anchor_id=first["tail_id"] + 10 ** 12, anchor_hash="1" * 64)
    assert missing["anchor"]["status"] == "MISSING" and missing["intact"] is False


def test_the_console_shows_the_caveat_and_the_tail_to_record():
    """The green tick and the sentence that qualifies it are drawn together
    (the custody panel always did), and both panels print the newest row an
    operator would record. Pure: reads the shipped asset."""
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http"
          / "static" / "app.js").read_text(encoding="utf-8")
    assert "if (r.windowed && r.caveat)" not in js, \
        "the audit panel still shows its caveat only for a windowed run"
    assert "Newest row to record: seq " in js
    assert "Newest row to record: id " in js
    assert "r.tail_row_hash" in js
