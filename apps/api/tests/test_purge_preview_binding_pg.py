"""A real purge destroys what its dry run counted, or nothing (over HTTP).

Final review U20, 2026-09-23. `POST /retention/purge` with `dry_run` false
took only a case and an authority and read what was due afresh, while the
console's confirmation repeated the counts of a dry run of any age. At
09:00 a dry run counts 3 exhibits and 11 held; at 11:00 a colleague lifts
the holds; at 14:00 "Destroy 3 exhibits" is confirmed and 14 go.

Now a dry run returns `preview`, a digest of the case, the authority and
every due item with its hold, and a real run must present it: 428 without
one, 409 when what is due has changed since. These drive that through the
router against a real database, with one exhibit whose hold is lifted
between the count and the confirmation, and never destroy anything: the
only real run that passes the gate has nothing actionable to act on. The
pure half (the digest, and one `as_of` for both reads of what is due) is
`test_purge_preview_binding.py`.

**The email prefix is `ppb-` and must stay unique**: the fixture cleans up
by deleting on it. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; purge binding is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

AUTHORITY = "scheduled retention run 2026-09"
EXPIRED = date(2026, 1, 1)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ppb-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"    OR case_id IN {csub}")
        c.execute("ALTER TABLE core.purge_tombstone DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.purge_tombstone WHERE purged_by IN {sub}")
        c.execute("ALTER TABLE core.purge_tombstone ENABLE TRIGGER USER")
        # Exhibits inserted directly (no custody rows), so they can go.
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ppb-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    import dataclasses

    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    # The destruction meter allows a burst of three, and one test here
    # makes six purge calls in a second. What is under test is the binding,
    # not the meter, so this client's meter is widened and nothing else is.
    limits = dict(LIMITS)
    limits["retention.destroy"] = dataclasses.replace(
        LIMITS["retention.destroy"], quota=100, burst=50)
    app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    return TestClient(app)


def _owner(conn):
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    store = PgUserStore(conn)
    uid = store.create_user(f"ppb-{uuid4().hex[:8]}@noctornal.test", "Ppb",
                            "correct-horse-battery-staple")
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'CASE_OWNER')", (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return uid, {"Authorization": f"Bearer {token}"}


def _expired_case_with_a_held_exhibit(conn, client, owner, auth):
    r = client.post("/api/v1/cases", headers=auth, json={
        "code": f"OP-PPB-{uuid4().hex[:6].upper()}", "title": "Operation PPB",
        "legal_basis": "production order 2026-0923",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    # Aged the way `test_governance_pg.py` ages one: `case_retention_sane`
    # ties retention to created_at, so the creation date moves too.
    conn.execute(
        '''UPDATE core."case"
              SET retention_until = %s, review_due = %s,
                  created_at = %s::date - interval '30 days'
            WHERE id = %s''',
        (EXPIRED, EXPIRED - timedelta(days=1), EXPIRED, case_id))
    evidence_id = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, acquired_by, acquired_at,
                acquisition_method, classification, legal_hold,
                legal_hold_reason)
           VALUES (%s, 'exhibit', 'text/plain', 10, %s, %s, %s, 'b', %s,
                   now(), 'MANUAL_UPLOAD', 'AMBER', true,
                   'court order 2026-11 names this exhibit')
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"key/{uuid4().hex}",
         owner)).fetchone()[0]
    return case_id, evidence_id


def _purge(client, auth, case_id, *, dry, preview=None, authority=AUTHORITY):
    body = {"case_id": case_id, "authority": authority, "dry_run": dry}
    if preview is not None:
        body["preview"] = preview
    return client.post("/api/v1/retention/purge", headers=auth, json=body)


def _set_hold(conn, evidence_id, on: bool):
    conn.execute(
        "UPDATE core.evidence SET legal_hold = %s, legal_hold_reason = %s "
        "WHERE id = %s",
        (on, "court order 2026-11 names this exhibit" if on else None,
         evidence_id))


def _alive(conn, evidence_id) -> bool:
    return conn.execute("SELECT purged_at IS NULL FROM core.evidence "
                        "WHERE id = %s", (evidence_id,)).fetchone()[0]


def test_a_hold_lifted_after_the_dry_run_voids_its_confirmation(conn, client):
    owner, auth = _owner(conn)
    case_id, exhibit = _expired_case_with_a_held_exhibit(conn, client,
                                                         owner, auth)

    # 09:00: the count. Nothing to destroy, one held back.
    counted = _purge(client, auth, case_id, dry=True)
    assert counted.status_code == 200, counted.text
    body = counted.json()
    assert body["evidence_purged"] == 0 and body["held_back"] == 1
    first = body["preview"]
    assert first and len(first) == 64

    # 11:00: a colleague lifts the hold. 14:00: the old count is confirmed.
    _set_hold(conn, exhibit, False)
    stale = _purge(client, auth, case_id, dry=False, preview=first)
    assert stale.status_code == 409, stale.text
    assert "Nothing was destroyed" in stale.json()["detail"]
    assert _alive(conn, exhibit)

    # A real run that names no dry run at all is refused before anything.
    blind = _purge(client, auth, case_id, dry=False)
    assert blind.status_code == 428, blind.text
    assert _alive(conn, exhibit)

    # A fresh dry run counts the exhibit, and its digest differs.
    recount = _purge(client, auth, case_id, dry=True).json()
    assert recount["evidence_purged"] == 1 and recount["held_back"] == 0
    assert recount["preview"] and recount["preview"] != first

    # The authority is part of what was confirmed: the tombstone keeps it.
    other = _purge(client, auth, case_id, dry=False, preview=recount["preview"],
                   authority="a different authority altogether")
    assert other.status_code == 409, other.text
    assert _alive(conn, exhibit)


def test_a_matching_preview_passes_the_gate(conn, client):
    """The binding refuses a stale confirmation and nothing else. The hold
    stays on, so the sweep that runs has nothing it may destroy."""
    owner, auth = _owner(conn)
    case_id, exhibit = _expired_case_with_a_held_exhibit(conn, client,
                                                         owner, auth)
    preview = _purge(client, auth, case_id, dry=True).json()["preview"]
    real = _purge(client, auth, case_id, dry=False, preview=preview)
    assert real.status_code == 200, real.text
    assert real.json()["dry_run"] is False
    assert real.json()["evidence_purged"] == 0
    assert real.json()["held_back"] == 1
    assert _alive(conn, exhibit)
