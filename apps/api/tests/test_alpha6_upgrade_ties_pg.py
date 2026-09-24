"""The two queries an operator runs around migration 0064, on a database
shaped the way Alpha 5.2 leaves one.

0064 makes a tie's confidence the highest grade among its live claims and
backfills every tie that disagreed. The Alpha 6 pre-release check
(2026-09-23) upgraded a populated Alpha 5.2 database and found two things
the notes did not tell an operator: the backfill RAISES a tie an analyst
had deliberately lowered with a correction beneath a claim that is still
live, and it writes no audit event for any tie it changes. So the upgrade
notes send the operator to two read-only queries under
`release/alpha6-upgrade/`, one to keep before upgrading and one to hand to
the analysts after. These tests run those files, as shipped, and hold them
to what the migration does:

- the BEFORE query lists exactly the ties the backfill changes, predicts
  the value each one ends at, and flags the ones an analyst had lowered;
- the AFTER query lists exactly the ties whose latest correction is lower
  than what the tie now holds, and not a tie the analyst lowered and then
  put back.

The Alpha 5.2 state is modelled as `test_tie_confidence_pg.py` models it
for the backfill test: rows written in a rolled-back transaction with the
user triggers off, because the Alpha 6 triggers refuse exactly the rows an
Alpha 5.2 database holds.

**The email prefix is `a6up-` and must stay unique**, for the reason
`test_graph_mutation_api_pg.py` gives: fixtures clean up on an email
pattern, and two files sharing one delete each other's rows.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import date
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the upgrade queries are gated"
)

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

ROOT = Path(__file__).resolve().parents[3]
UPGRADE = ROOT / "release" / "alpha6-upgrade"
MIGRATION = ROOT / "db" / "migrations" / "versions" / "0064_edge_confidence_source.py"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()  # autocommit
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'a6up-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'a6up-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _owner(conn) -> str:
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    store = PgUserStore(conn)
    uid = store.create_user(f"a6up-{uuid4().hex[:8]}@noctornal.test", "A6Up", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s", (uid,))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'CASE_OWNER')", (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(client, token) -> tuple[str, str]:
    code = f"OP-A6UP-{uuid4().hex[:6]}"
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": code, "title": "Operation Upgrade",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"], code


def _node(client, token, case_id, label) -> str:
    # Graded explicitly: the API grades nothing for the caller since
    # gap-api-grade-required (2026-09-23).
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json={"node_type": "IDENTITY", "label": label,
                          "assertion": {"basis": "DIRECT_OBSERVATION",
                                        "reliability": "B", "credibility": "2",
                                        "confidence": "MODERATE"}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _tie(client, token, case_id, src, dst, confidence) -> str:
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json={"edge_type": "VOUCHED_FOR", "src_node_id": src,
                          "dst_node_id": dst,
                          "assertion": {"basis": "DIRECT_OBSERVATION",
                                        "reliability": "B", "credibility": "2",
                                        "confidence": confidence}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _m0064():
    spec = importlib.util.spec_from_file_location("m0064", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(tx, name: str, case_code: str) -> dict[str, dict]:
    """The shipped file, executed as it stands, rows of this case only."""
    from psycopg.rows import dict_row

    sql = (UPGRADE / name).read_text(encoding="utf-8")
    with tx.cursor(row_factory=dict_row) as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    return {str(r["edge_id"]): r for r in rows if r["case_code"] == case_code}


def test_the_queries_around_0064_name_the_ties_it_changes(conn, client):
    """Six ties, each one a shape the check met on real Alpha 5.2 data:

    - lowered: graded MODERATE, then corrected down to LOW. The backfill
      raises it back to MODERATE, and both queries must say so.
    - restored: lowered to LOW and later put back to MODERATE. The
      analyst's last word stands, so neither query lists it; a query that
      compared every live correction with the tie, not only the latest,
      would.
    - drifted: graded HIGH, stored LOW, the Alpha 5.2 default nobody chose.
      The backfill repairs it; no analyst lowered it.
    - lowered_deleted: lowered, then soft-deleted. Still changed, and
      flagged as deleted.
    - raised_later: lowered to LOW, then a HIGH claim added afterwards,
      which Alpha 5.2 never carried to the column. Listed after the
      upgrade too, for an analyst to judge rather than redo.
    - untouched: graded LOW and stored LOW. Nothing to say.
    """
    import psycopg

    from noctornal_api.db import dsn

    token = _owner(conn)
    case_id, code = _case(client, token)
    n = [_node(client, token, case_id, f"n{i}") for i in range(7)]
    lowered = _tie(client, token, case_id, n[0], n[1], "MODERATE")
    restored = _tie(client, token, case_id, n[1], n[2], "MODERATE")
    drifted = _tie(client, token, case_id, n[2], n[3], "HIGH")
    lowered_deleted = _tie(client, token, case_id, n[3], n[4], "HIGH")
    raised_later = _tie(client, token, case_id, n[4], n[5], "MODERATE")
    untouched = _tie(client, token, case_id, n[5], n[6], "LOW")
    ours = [lowered, restored, drifted, lowered_deleted, raised_later, untouched]
    uid = conn.execute("SELECT created_by FROM core.edge WHERE id = %s",
                       (lowered,)).fetchone()[0]

    def correction(tx, edge, value, minutes_ago):
        # What an Alpha 5.2 PATCH wrote: a correction graded LOW whatever
        # it said, the value in claim_value, and the column set directly.
        tx.execute(
            """INSERT INTO core.assertion (case_id, edge_id, basis, confidence,
                   rationale, claim_path, claim_value, created_by, recorded_at)
               VALUES (%s, %s, 'DIRECT_OBSERVATION', 'LOW', 'corrected',
                       'confidence', jsonb_build_object('confidence', %s::text),
                       %s, now() - make_interval(mins => %s))""",
            (case_id, edge, value, uid, minutes_ago))
        tx.execute("UPDATE core.edge SET confidence = %s WHERE id = %s",
                   (value, edge))

    m = _m0064()
    tx = psycopg.connect(dsn())
    try:
        tx.execute("ALTER TABLE core.edge DISABLE TRIGGER USER")
        tx.execute("ALTER TABLE core.assertion DISABLE TRIGGER USER")
        correction(tx, lowered, "LOW", 5)
        correction(tx, restored, "LOW", 5)
        correction(tx, restored, "MODERATE", 2)
        tx.execute("UPDATE core.edge SET confidence = 'LOW' WHERE id = %s", (drifted,))
        correction(tx, lowered_deleted, "LOW", 5)
        tx.execute("UPDATE core.edge SET deleted_at = now(), deleted_by = %s "
                   "WHERE id = %s", (uid, lowered_deleted))
        correction(tx, raised_later, "LOW", 5)
        tx.execute(
            """INSERT INTO core.assertion (case_id, edge_id, basis, confidence,
                   created_by, recorded_at)
               VALUES (%s, %s, 'DIRECT_OBSERVATION', 'HIGH', %s,
                       now() - make_interval(mins => 1))""",
            (case_id, raised_later, uid))
        tx.execute("ALTER TABLE core.edge ENABLE TRIGGER USER")
        tx.execute("ALTER TABLE core.assertion ENABLE TRIGGER USER")

        stored = dict(tx.execute(
            "SELECT id::text, confidence::text FROM core.edge WHERE id = ANY(%s)",
            (ours,)).fetchall())
        assert stored == {lowered: "LOW", restored: "MODERATE", drifted: "LOW",
                          lowered_deleted: "LOW", raised_later: "LOW",
                          untouched: "LOW"}, "the Alpha 5.2 state was not modelled"

        before = _run(tx, "0064-ties-before.sql", code)
        assert set(before) == {lowered, drifted, lowered_deleted, raised_later}
        flags = {e: (str(r["now_value"]), str(r["alpha6_value"]),
                     r["last_correction"] and str(r["last_correction"]),
                     r["analyst_lowered"], r["soft_deleted"])
                 for e, r in before.items()}
        assert flags == {
            lowered: ("LOW", "MODERATE", "LOW", True, False),
            drifted: ("LOW", "HIGH", None, False, False),
            lowered_deleted: ("LOW", "HIGH", "LOW", True, True),
            raised_later: ("LOW", "HIGH", "LOW", True, False),
        }

        tx.execute(m.BACKFILL_SQL)
        after_backfill = dict(tx.execute(
            "SELECT id::text, confidence::text FROM core.edge WHERE id = ANY(%s)",
            (ours,)).fetchall())
        changed = {e for e in ours if after_backfill[e] != stored[e]}
        assert changed == set(before), (
            "the before query must list exactly the ties the backfill changes")
        for edge, row in before.items():
            assert after_backfill[edge] == str(row["alpha6_value"]), (
                f"the before query predicted {row['alpha6_value']} for {edge}, "
                f"the backfill wrote {after_backfill[edge]}")

        after = _run(tx, "0064-ties-after.sql", code)
        assert set(after) == {lowered, lowered_deleted, raised_later}, (
            "the after query lists the ties whose latest correction is lower "
            "than the tie, and not the one the analyst put back")
        assert all(str(r["last_correction"]) == "LOW" for r in after.values())
        assert after[lowered_deleted]["soft_deleted"] is True
        assert after[lowered]["corrected_by"].startswith("a6up-")
    finally:
        tx.rollback()
        tx.close()
