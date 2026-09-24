"""What an administrator-issued password opens, and what a refused sign-in
spends (final review of Alpha 6, 2026-09-24).

- c8: a password an administrator issues when CREATING an account is
  known to the administrator, with the TOTP seed beside it, exactly as a
  reset password is. It now has to be replaced at the account's first
  sign-in; the first-run administrator, who made their own account, is
  not asked to. `bootstrap.py create-user` follows the same line: the
  first account on an empty database is the operator's own, and any later
  one (the installers' Security Officer advice) is someone else's.
- u4: the must-change refusal (403) and the no-change-pending refusal
  (409) came after `authenticate` had spent a single-use recovery code,
  so finishing one reset cost two codes, and the last code could never
  finish it. A recovery code is now spent only by a sign-in that mints a
  session, and a concurrent spend of the same code still wins once.
- u22: `last_login_at`, which the Admin card calls "last password
  sign-in", was stamped by the 403 and 409 refusals and by an Account
  password change, none of which signs anyone in.

Email prefix `isp-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from uuid import UUID, uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; sign-in spend is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"
TYPE = "urn:noctornal:problem:password-change-required"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'isp-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'isp-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _email() -> str:
    return f"isp-{uuid4().hex[:8]}@noctornal.test"


def _make_user(conn, *, global_roles=("ANALYST",)):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = _email()
    store = PgUserStore(conn)
    uid = store.create_user(email, "Isp", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _session(conn, uid) -> str:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _code(conn, uid, secret) -> str:
    """A code the server accepts now: the replay counter is cleared first,
    because this file signs in more than once per 30-second step."""
    from noctornal_api.security import totp
    conn.execute("UPDATE iam.app_user SET totp_last_counter = NULL WHERE id = %s",
                 (uid,))
    return totp.code_at(secret, int(time.time()))


def _row(conn, uid) -> tuple:
    """(must_change_password, last_login_at, recovery codes left)."""
    return conn.execute(
        """SELECT must_change_password, last_login_at,
                  coalesce(cardinality(recovery_codes_hash), 0)
             FROM iam.app_user WHERE id = %s""", (uid,)).fetchone()


def _live_sessions(conn, uid) -> int:
    return conn.execute(
        "SELECT count(*) FROM iam.session WHERE user_id = %s AND revoked_at IS NULL",
        (uid,)).fetchone()[0]


def _cookie(r) -> bool:
    from noctornal_api.http.deps import SESSION_COOKIE
    return any(c.startswith(f"{SESSION_COOKIE}=")
               for c in r.headers.get_list("set-cookie"))


def _svc(conn):
    from noctornal_api.iam_admin import IamAdminService
    return IamAdminService(conn)


# --- c8: a created account's password ---------------------------------------

def test_a_created_accounts_issued_password_must_be_replaced(conn):
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    creds = _svc(conn).create_analyst(
        email=_email(), display_name="New", clearance="AMBER",
        roles=["ANALYST"], actor_id=admin)
    assert _row(conn, creds.user_id)[0] is True, (
        "a password the administrator was shown opens sessions indefinitely")
    detail = conn.execute(
        """SELECT detail FROM audit.event
            WHERE object_id = %s AND action = 'USER_CREATED'""",
        (creds.user_id,)).fetchone()[0]
    assert detail["must_change_password"] is True


def test_a_panel_created_account_signs_in_only_with_a_password_of_its_own(
        conn, client):
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    r = client.post("/api/v1/admin/users", headers=_auth(_session(conn, admin)),
                    json={"email": _email(), "display_name": "Panel",
                          "roles": ["ANALYST"]})
    assert r.status_code == 201, r.text
    created = r.json()
    assert "first sign-in" in created["notice"]
    uid = UUID(created["user_id"])

    r = client.post("/api/v1/auth/login", json={
        "email": created["email"], "password": created["password"],
        "totp_code": _code(conn, uid, created["totp_secret"])})
    assert r.status_code == 403, r.text
    assert r.json()["type"] == TYPE
    assert not _cookie(r) and _live_sessions(conn, uid) == 0, (
        "the issued password minted a session")

    r = client.post("/api/v1/auth/login", json={
        "email": created["email"], "password": created["password"],
        "totp_code": _code(conn, uid, created["totp_secret"]),
        "new_password": "a passphrase of their own"})
    assert r.status_code == 204, r.text
    assert _cookie(r) and _row(conn, uid)[0] is False


def test_the_first_run_administrator_is_not_asked_to_replace_their_own(
        conn, monkeypatch):
    """First run creates the operator's OWN account and proves it by
    signing in on the same card, so it keeps its password. The door is
    shut on a populated database, so the emptiness check and the create
    are stood in for, and what is asserted is what first run asks for."""
    from noctornal_api import iam_admin
    asked = {}

    def record(self, **kwargs):
        asked.update(kwargs)
        return None

    monkeypatch.setattr(iam_admin, "needs_setup", lambda c: True)
    monkeypatch.setattr(iam_admin.IamAdminService, "create_analyst", record)
    iam_admin.create_first_admin(conn, email=_email(), display_name="First")
    assert asked["must_change_password"] is False
    assert asked["actor_id"] is None


def test_an_account_created_without_the_flag_keeps_its_password(conn, client):
    """The same service call first run makes, for real: no flag, and the
    issued credentials open a session at once."""
    creds = _svc(conn).create_analyst(
        email=_email(), display_name="Own", clearance="AMBER",
        roles=["ANALYST"], actor_id=None, must_change_password=False)
    assert _row(conn, creds.user_id)[0] is False
    r = client.post("/api/v1/auth/login", json={
        "email": creds.email, "password": creds.password,
        "totp_code": _code(conn, creds.user_id, creds.totp_secret)})
    assert r.status_code == 204, r.text


def _bootstrap():
    import sys
    from pathlib import Path
    scripts = Path(__file__).resolve().parents[3] / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bootstrap
    return bootstrap


def _create_user(capsys, email: str, roles: str) -> str:
    import argparse
    bootstrap = _bootstrap()
    bootstrap.cmd_create_user(argparse.Namespace(
        email=email, name="Created Here", password=PASSWORD,
        clearance="AMBER", roles=roles))
    return capsys.readouterr().out


def _printed_secret(out: str) -> str:
    lines = out.splitlines()
    return lines[lines.index("  TOTP secret (base32):") + 1].strip()


def _created_detail(conn, uid) -> dict:
    return conn.execute(
        """SELECT detail FROM audit.event
            WHERE object_id = %s AND action = 'USER_CREATED'""",
        (uid,)).fetchone()[0]


def test_bootstrap_create_user_flags_an_account_for_someone_else(
        conn, client, capsys):
    """The verifier's case on c8: the installers advise `create-user ...
    --roles SECURITY_OFFICER` once the operator's own account exists, and
    that password opened the officer's sessions, under the officer's id,
    for the operator who printed it. On a database that already has an
    account, create-user now issues a password that must be replaced."""
    email = _email()
    out = _create_user(capsys, email, "SECURITY_OFFICER")
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    assert _row(conn, uid)[0] is True, (
        "a password the operator printed for someone else opens their sessions")
    assert _created_detail(conn, uid)["must_change_password"] is True
    assert "The password above opens no session" in out
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": _code(conn, uid, _printed_secret(out))})
    assert r.status_code == 403, r.text
    assert r.json()["type"] == TYPE
    assert not _cookie(r) and _live_sessions(conn, uid) == 0


def test_bootstrap_create_user_leaves_the_operators_first_account_alone(
        conn, client, capsys, monkeypatch):
    """The first account on an empty database is the operator's own, the
    one the installer makes: it keeps the password printed for it. This
    clone is never empty, so the emptiness read is stood in for."""
    bootstrap = _bootstrap()
    monkeypatch.setattr(bootstrap, "_issued_to_someone_else", lambda c: False)
    email = _email()
    out = _create_user(capsys, email, "CASE_OWNER,SYS_ADMIN")
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    assert _row(conn, uid)[0] is False
    assert _created_detail(conn, uid)["must_change_password"] is False
    assert "opens no session" not in out
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": _code(conn, uid, _printed_secret(out))})
    assert r.status_code == 204, r.text


def test_the_someone_else_read_is_whether_any_account_exists(conn):
    assert _bootstrap()._issued_to_someone_else(conn) is True

    class Empty:
        def execute(self, sql):
            assert "FROM iam.app_user" in sql
            return self

        def fetchone(self):
            return (False,)

    assert _bootstrap()._issued_to_someone_else(Empty()) is False


# --- u4: a refused sign-in spends no recovery code --------------------------

def test_the_must_change_refusal_spends_no_recovery_code(conn, client):
    from noctornal_api.stores import PgUserStore
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, email, _ = _make_user(conn)
    codes = PgUserStore(conn).issue_recovery_codes(uid, 1)
    one_time = _svc(conn).reset_password(uid, actor_id=admin).password

    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": one_time, "totp_code": codes[0]})
    assert r.status_code == 403, r.text
    assert r.json()["type"] == TYPE
    assert _row(conn, uid) == (True, None, 1), (
        "the refusal spent the last recovery code or recorded a sign-in")

    # The same, last, code finishes the change, and is spent by it.
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": one_time, "totp_code": codes[0],
        "new_password": "a passphrase of my own"})
    assert r.status_code == 204, r.text
    must, last_login, left = _row(conn, uid)
    assert (must, left) == (False, 0) and last_login is not None
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": "a passphrase of my own",
        "totp_code": codes[0]})
    assert r.status_code == 401, "a recovery code worked twice"


def test_the_no_change_pending_refusal_spends_no_recovery_code(conn, client):
    from noctornal_api.stores import PgUserStore
    uid, email, _ = _make_user(conn)
    codes = PgUserStore(conn).issue_recovery_codes(uid, 1)
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD, "totp_code": codes[0],
        "new_password": "something else entirely"})
    assert r.status_code == 409, r.text
    assert _row(conn, uid) == (False, None, 1)
    assert _live_sessions(conn, uid) == 0


def test_a_recovery_code_spent_meanwhile_still_wins_once(
        conn, client, monkeypatch):
    """Verifying a code no longer spends it, so the spend can race. The
    atomic remove still decides: a code another sign-in spent between
    this one's check and its spend is a 401, and nothing is changed."""
    from noctornal_api.security import passwords
    from noctornal_api.stores import PgUserStore
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, email, _ = _make_user(conn)
    codes = PgUserStore(conn).issue_recovery_codes(uid, 1)
    one_time = _svc(conn).reset_password(uid, actor_id=admin).password
    real = PgUserStore.consume_recovery_hash

    def raced(self, user_id, code_hash):
        real(self, user_id, code_hash)          # the other sign-in wins
        return real(self, user_id, code_hash)   # and this one finds it gone

    monkeypatch.setattr(PgUserStore, "consume_recovery_hash", raced)
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": one_time, "totp_code": codes[0],
        "new_password": "a passphrase of my own"})
    assert r.status_code == 401, r.text
    assert not _cookie(r) and _live_sessions(conn, uid) == 0
    stored = conn.execute("SELECT password_hash FROM iam.app_user WHERE id = %s",
                          (uid,)).fetchone()[0]
    assert passwords.verify_password(stored, one_time), (
        "a sign-in whose code was spent under it still changed the password")
    assert _row(conn, uid)[:2] == (True, None)


# --- u22: last password sign-in is a sign-in --------------------------------

def test_a_refusal_and_an_account_change_record_no_sign_in(conn, client):
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, email, secret = _make_user(conn)
    one_time = _svc(conn).reset_password(uid, actor_id=admin).password
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": one_time,
        "totp_code": _code(conn, uid, secret)})
    assert r.status_code == 403, r.text
    assert _row(conn, uid)[1] is None, (
        "a sign-in that opened no session reads as the last sign-in")

    other, _, other_secret = _make_user(conn)
    r = client.post("/api/v1/auth/password",
                    headers=_auth(_session(conn, other)), json={
                        "current_password": PASSWORD,
                        "totp_code": _code(conn, other, other_secret),
                        "new_password": "a brand new passphrase"})
    assert r.status_code == 200, r.text
    assert _row(conn, other)[1] is None, (
        "changing a password from Account reads as a sign-in")

    # An ordinary sign-in is still recorded, and a failed one clears nothing.
    r = client.post("/api/v1/auth/login", json={
        "email": _row_email(conn, other), "password": "a brand new passphrase",
        "totp_code": _code(conn, other, other_secret)})
    assert r.status_code == 204, r.text
    assert _row(conn, other)[1] is not None


def _row_email(conn, uid) -> str:
    return conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                        (uid,)).fetchone()[0]


def test_a_refused_sign_in_still_resets_the_failure_count(conn, client):
    """Moving the sign-in stamp out of `clear_failed_logins` must not move
    the reset with it: both factors were right, so the typos before this
    sign-in no longer count toward a lockout."""
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, email, secret = _make_user(conn)
    one_time = _svc(conn).reset_password(uid, actor_id=admin).password
    conn.execute("UPDATE iam.app_user SET failed_logins = 3 WHERE id = %s", (uid,))
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": one_time,
        "totp_code": _code(conn, uid, secret)})
    assert r.status_code == 403, r.text
    assert conn.execute("SELECT failed_logins FROM iam.app_user WHERE id = %s",
                        (uid,)).fetchone()[0] == 0
