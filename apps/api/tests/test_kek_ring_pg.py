"""The key ring against the database: the readiness check that proves
the ring OPENS what is stored, the login that refuses by name, and the
rotation runbook run end to end -- and then run back.

Env-gated on DATABASE_URL. The HOME key is whatever `NOCTORNAL_TOTP_KEK`
the process started with (the suite's `A`*43+`=` on CI, `.env.local`'s on
a developer machine); every fixture enrols under it, this file rotates
AWAY from it and, in a `finally`, rotates BACK, so the rows it re-sealed
are left under the home key with fresh nonces and nothing else in the
suite can tell.

A developer database may already hold rows under a key this process no
longer has -- this one did, 65 accounts and 69 samples sealed by a
`.env.local` that was regenerated -- all recorded under `env:v1`. The
assertions are therefore RELATIVE to what the inventory finds: the rows
this file creates must flip, and the rows it did not create must be left
exactly as found. On CI's fresh database the baseline is zero and every
assertion is strict.

**The email prefix is `kek-` and must stay unique.**
"""
from __future__ import annotations

import base64
import os
import time
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; KEK ring e2e is gated")

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
HOME_KEK = os.environ["NOCTORNAL_TOTP_KEK"]

OTHER_KEK = base64.b64encode(b"rotated-kek-32-bytes-exactly!!!!").decode()
CHECK = "kek_ring_opens_stored_secrets"
USERS = ("iam.app_user", "env:v1")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'kek-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'kek-%@noctornal.test'")
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
def ring(monkeypatch):
    """Set the ring; monkeypatch puts the home key back afterwards."""
    def _set(*, active=HOME_KEK, active_id=None, retired=None):
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK", active)
        for name, value in (("NOCTORNAL_TOTP_KEK_ID", active_id),
                            ("NOCTORNAL_TOTP_KEK_RETIRED", retired)):
            if value is None:
                monkeypatch.delenv(name, raising=False)
            else:
                monkeypatch.setenv(name, value)
    _set()
    return _set


def _enrolled(conn):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"kek-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Ring", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    return uid, email, secret


def _row(conn, uid) -> tuple[bytes, str]:
    blob, key_id = conn.execute(
        "SELECT totp_secret_ciphertext, totp_key_id FROM iam.app_user WHERE id = %s",
        (uid,)).fetchone()
    return bytes(blob), key_id


def _login(client, conn, uid, email, secret):
    from noctornal_api.security import totp
    # TOTP codes are single-use per 30-second step and this file signs
    # the same account in several times, so the replay counter is reset
    # between attempts. The replay guard has its own tests.
    conn.execute("UPDATE iam.app_user SET totp_last_counter = NULL WHERE id = %s", (uid,))
    return client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})


def _check(conn) -> dict:
    from noctornal_api import readiness
    return next(c for c in readiness.report(conn)["checks"] if c["check"] == CHECK)


def _groups(conn) -> dict:
    from noctornal_api.security.sealed import inventory
    return {(g.table, g.key_id): g for g in inventory(conn)}


def test_the_register_sees_a_key_that_changed_under_its_id(conn, ring):
    """`totp_kek_set` stays green through all of this: the other key is
    32 bytes. The ring check opens rows and counts, and reports the
    table, the count and which of the two faults it is."""
    from noctornal_api.security import envelope
    uid, _, _ = _enrolled(conn)
    blob, key_id = _row(conn, uid)
    assert key_id == "env:v1"
    assert envelope.can_open(blob, key_id=key_id) is None
    baseline = sum(g.unopenable for g in _groups(conn).values())
    ok = _check(conn)
    assert ok["ok"] is (baseline == 0), ok
    assert "active env:v1" in ok["evidence"]

    ring(active=OTHER_KEK)                                  # rotated, id kept
    problem = envelope.can_open(blob, key_id=key_id)
    assert problem and "does not open" in problem
    users = _groups(conn)[USERS]
    assert users.checked >= 1 and users.unopenable == users.checked
    bad = _check(conn)
    assert bad["ok"] is False, bad
    assert "iam.app_user" in bad["evidence"] and "does not open" in bad["evidence"]
    assert "rewrap_secrets" in bad["action"]
    assert OTHER_KEK not in bad["evidence"] and HOME_KEK not in bad["evidence"]

    ring(active=OTHER_KEK, active_id="env:v2")              # id moved, home key gone
    assert "no key with id 'env:v1'" in envelope.can_open(blob, key_id=key_id)
    gone = _check(conn)
    assert gone["ok"] is False and "no key with id 'env:v1'" in gone["evidence"]

    ring(active=OTHER_KEK, active_id="env:v2", retired=f"env:v1={HOME_KEK}")
    assert envelope.can_open(blob, key_id=key_id) is None
    assert sum(g.unopenable for g in _groups(conn).values()) == baseline
    retired = _check(conn)
    assert retired["ok"] is (baseline == 0), retired
    assert "retired env:v1" in retired["evidence"]
    if baseline == 0:
        assert "rewrap_secrets" in retired["evidence"], "rows under a retired id remain"


def test_login_refuses_by_name_when_the_secret_cannot_be_opened(conn, client, ring):
    """503, the readiness check named, the password NOT reported wrong,
    and no lockout attempt burnt -- where there was a 500."""
    uid, email, secret = _enrolled(conn)
    assert _login(client, conn, uid, email, secret).status_code == 204

    ring(active=OTHER_KEK)
    r = _login(client, conn, uid, email, secret)
    assert r.status_code == 503, r.text
    assert CHECK in r.json()["detail"]
    assert "credentials" in r.json()["detail"]
    assert conn.execute("SELECT failed_logins FROM iam.app_user WHERE id = %s",
                        (uid,)).fetchone()[0] == 0
    audited = conn.execute(
        """SELECT detail->>'reason' FROM audit.event
            WHERE action = 'AUTH_FAILED' AND actor_id = %s
            ORDER BY seq DESC LIMIT 1""", (uid,)).fetchone()
    assert audited and audited[0] == "totp_secret_unopenable"


def test_the_rotation_runbook_end_to_end_and_back(conn, client, ring):
    """The four steps of `security/envelope.py`, with a login after each:
    rotate with the old key retired, re-wrap, drop the retired key. Then
    the same in reverse, so the database leaves this test under the home
    key. Rows the ring cannot open are left exactly where they were, and
    counted."""
    from noctornal_api.security.sealed import rewrap_all
    uid, email, secret = _enrolled(conn)
    before = _groups(conn)
    foreign = sum(g.unopenable for g in before.values())

    try:
        # 1 + 2: new active key under a new id, old key retired under its id.
        ring(active=OTHER_KEK, active_id="env:v2", retired=f"env:v1={HOME_KEK}")
        assert _login(client, conn, uid, email, secret).status_code == 204
        assert _row(conn, uid)[1] == "env:v1"
        # 3: re-wrap. Every row the ring opens moves; the rest stay put.
        reports = {r.table: r for r in rewrap_all(conn)}
        assert reports["iam.app_user"].rewrapped >= 1
        assert _row(conn, uid)[1] == "env:v2"
        after = _groups(conn)
        assert after[("iam.app_user", "env:v2")].opens
        left_behind = sum(g.rows for (_, k), g in after.items() if k == "env:v1")
        assert left_behind == sum(r.unopenable for r in reports.values()) == foreign
        # 4: the retired key is dropped, and everything that moved still opens.
        ring(active=OTHER_KEK, active_id="env:v2")
        assert _login(client, conn, uid, email, secret).status_code == 204
        assert _check(conn)["ok"] is (foreign == 0)
    finally:
        # Back: the home key becomes active under env:v1 again, the rotated
        # key retires under env:v2, and the re-wrap brings every row home.
        # Unconditional, because a half-rotated database fails every other
        # login in the suite with the 503 this file tests.
        ring(active=HOME_KEK, active_id="env:v1", retired=f"env:v2={OTHER_KEK}")
        rewrap_all(conn)
        ring(active=HOME_KEK)
    assert _row(conn, uid)[1] == "env:v1"
    assert _login(client, conn, uid, email, secret).status_code == 204
    home = _groups(conn)
    assert all(k == "env:v1" for (_, k) in home), sorted(home)
    assert sum(g.unopenable for g in home.values()) == foreign
    assert _check(conn)["ok"] is (foreign == 0)
