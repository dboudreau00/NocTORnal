"""Administrator-issued password reset, the must-change sign-in and the
Account password change (gap-password-reset, 2026-09-23).

There was no password reset anywhere: not in the console, not in the API,
not in `scripts/bootstrap.py`. The owner decided it is administrator
issued, with no email path. What these tests carry:

- the reset is `user.manage` with step-up, refused for oneself, audited,
  revokes every live session and clears the lockout, and the one-time
  password it returns works exactly once and never opens a session;
- sign-in with that password answers 403 with a machine-readable type and
  mints NOTHING, and the same sign-in carrying a new password stores it,
  clears the flag and signs in;
- a new password is judged before any credential is, so a rule failure
  costs no lockout attempt and spends no code;
- a person changes their own password with the current one and a code,
  a wrong current password counts toward the lockout like a wrong
  sign-in, and every other session is signed out;
- `bootstrap.py reset-password` is the same reset from the shell.

Email prefix `pwr-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import io
import os
import time
from contextlib import redirect_stdout
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; password reset is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"
TYPE = "urn:noctornal:problem:password-change-required"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'pwr-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'pwr-%@noctornal.test'")
        c.execute("DELETE FROM iam.compartment WHERE key LIKE 'PWR-%'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, global_roles=("ANALYST",)):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"pwr-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Pwr", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _session(conn, uid, *, fresh=True) -> tuple:
    """A session minted the way `bootstrap.py session` mints one. `fresh`
    False backdates its second factor past the step-up window."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    record, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    if not fresh:
        conn.execute(
            "UPDATE iam.session SET mfa_satisfied_at = now() - interval '2 hours'"
            " WHERE id = %s", (record.id,))
    return record.id, token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _code(conn, uid, secret) -> str:
    """A code the server will accept now. Codes are single use, so the
    replay counter is cleared first: this file signs in more than once per
    30-second step, and a replay refusal would be about the test's pace,
    not about the thing under test."""
    from noctornal_api.security import totp
    conn.execute("UPDATE iam.app_user SET totp_last_counter = NULL WHERE id = %s",
                 (uid,))
    return totp.code_at(secret, int(time.time()))


def _live_sessions(conn, uid) -> int:
    return conn.execute(
        "SELECT count(*) FROM iam.session WHERE user_id = %s AND revoked_at IS NULL",
        (uid,)).fetchone()[0]


def _flag(conn, uid) -> bool:
    return conn.execute(
        "SELECT must_change_password FROM iam.app_user WHERE id = %s",
        (uid,)).fetchone()[0]


def _audit(conn, uid, action) -> list:
    return conn.execute(
        """SELECT actor_kind, detail FROM audit.event
            WHERE object_id = %s AND action = %s ORDER BY seq""",
        (uid, action)).fetchall()


def _svc(conn):
    from noctornal_api.iam_admin import IamAdminService
    return IamAdminService(conn)


# --- the service --------------------------------------------------------

def test_a_reset_sets_the_flag_revokes_sessions_clears_the_lock_and_audits(conn):
    from noctornal_api.security import passwords
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, _, _ = _make_user(conn)
    _session(conn, uid)
    _session(conn, uid)
    conn.execute("""UPDATE iam.app_user SET failed_logins = 5,
                    locked_until = now() + interval '10 minutes' WHERE id = %s""",
                 (uid,))

    creds = _svc(conn).reset_password(uid, actor_id=admin)

    assert creds.password and not creds.totp_secret and not creds.otpauth_uri
    row = conn.execute(
        """SELECT password_hash, must_change_password, failed_logins,
                  locked_until, password_changed_at
             FROM iam.app_user WHERE id = %s""", (uid,)).fetchone()
    assert passwords.verify_password(row[0], creds.password)
    assert not passwords.verify_password(row[0], PASSWORD), (
        "the old password still works after a reset")
    assert row[1] is True and row[2] == 0 and row[3] is None and row[4]
    assert _live_sessions(conn, uid) == 0, "a reset left a session standing"
    [(kind, detail)] = _audit(conn, uid, "PASSWORD_RESET")
    assert kind == "USER" and detail["sessions_revoked"] == 2
    assert detail["via"] == "admin" and detail["was_locked_until"]


def test_an_administrator_cannot_reset_their_own_password(conn):
    from noctornal_api.iam_admin import AdminError
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    with pytest.raises(AdminError, match="your own password"):
        _svc(conn).reset_password(admin, actor_id=admin)
    assert _flag(conn, admin) is False


def test_resetting_nobody_is_a_404_shaped_refusal(conn):
    from noctornal_api.iam_admin import AdminError
    with pytest.raises(AdminError, match="no such user"):
        _svc(conn).reset_password(uuid4(), actor_id=uuid4())


def test_the_password_rules_are_length_and_not_the_obvious(conn):
    from noctornal_api.iam_admin import new_password_problem
    email = "someone@noctornal.test"
    assert "at least 12" in new_password_problem("short", email=email)
    assert "at most" in new_password_problem("x" * 1025, email=email)
    assert "being replaced" in new_password_problem(
        "the-very-same-one", email=email, current="the-very-same-one")
    assert "email" in new_password_problem("someone@noctornal.test", email=email)
    assert new_password_problem("a long enough phrase", email=email) is None


# --- over HTTP: who may reset ---------------------------------------------

def test_the_reset_route_is_user_manage_with_step_up_and_not_for_oneself(
        conn, client):
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    analyst, _, _ = _make_user(conn)
    target, _, _ = _make_user(conn)
    url = f"/api/v1/admin/users/{target}/password"

    assert client.post(url).status_code == 401
    _, analyst_token = _session(conn, analyst)
    r = client.post(url, headers=_auth(analyst_token))
    assert r.status_code == 403 and "user.manage" in r.json()["detail"]

    _, stale = _session(conn, admin, fresh=False)
    r = client.post(url, headers=_auth(stale))
    assert r.status_code == 403, r.text
    assert "re-authentication" in r.json()["detail"]
    assert _flag(conn, target) is False, "a stale session reset a password"

    _, token = _session(conn, admin)
    r = client.post(f"/api/v1/admin/users/{admin}/password", headers=_auth(token))
    assert r.status_code == 409 and "your own password" in r.json()["detail"]

    r = client.post(url, headers=_auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["password"] and body["totp_secret"] is None
    assert body["otpauth_uri"] is None
    assert "choose their own password" in body["notice"]
    assert _flag(conn, target) is True


# --- the sign-in that follows ------------------------------------------------

def test_the_one_time_password_never_opens_a_session(conn, client):
    from noctornal_api.http.deps import SESSION_COOKIE
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, email, secret = _make_user(conn)
    creds = _svc(conn).reset_password(uid, actor_id=admin)

    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": creds.password,
        "totp_code": _code(conn, uid, secret)})
    assert r.status_code == 403, r.text
    assert r.json()["type"] == TYPE
    assert not [c for c in r.headers.get_list("set-cookie")
                if c.startswith(f"{SESSION_COOKIE}=")], (
        "the one-time password minted a session")
    assert _live_sessions(conn, uid) == 0
    assert conn.execute(
        """SELECT 1 FROM audit.event WHERE actor_id = %s
            AND action = 'AUTH_PASSWORD_CHANGE_REQUIRED'""", (uid,)).fetchone()

    # And the old password is simply wrong now: an ordinary 401.
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": _code(conn, uid, secret)})
    assert r.status_code == 401


def test_the_sign_in_with_a_new_password_stores_it_and_signs_in(conn, client):
    from noctornal_api.http.deps import SESSION_COOKIE
    from noctornal_api.security import passwords
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, email, secret = _make_user(conn)
    creds = _svc(conn).reset_password(uid, actor_id=admin)
    chosen = "my own long passphrase 42"

    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": creds.password,
        "totp_code": _code(conn, uid, secret), "new_password": chosen})
    assert r.status_code == 204, r.text
    assert [c for c in r.headers.get_list("set-cookie")
            if c.startswith(f"{SESSION_COOKIE}=")]
    assert _flag(conn, uid) is False
    stored = conn.execute("SELECT password_hash FROM iam.app_user WHERE id = %s",
                          (uid,)).fetchone()[0]
    assert passwords.verify_password(stored, chosen)
    assert not passwords.verify_password(stored, creds.password)
    [(_, detail)] = _audit(conn, uid, "PASSWORD_CHANGED")
    assert detail["via"] == "sign-in after a reset"

    # The one-time password is spent for good.
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": creds.password,
        "totp_code": _code(conn, uid, secret)})
    assert r.status_code == 401


def test_a_bad_new_password_costs_no_attempt_and_no_code(conn, client):
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, email, secret = _make_user(conn)
    creds = _svc(conn).reset_password(uid, actor_id=admin)
    code = _code(conn, uid, secret)

    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": creds.password, "totp_code": code,
        "new_password": "short"})
    assert r.status_code == 422, r.text
    assert "at least 12" in r.json()["detail"]
    row = conn.execute(
        "SELECT failed_logins, totp_last_counter FROM iam.app_user WHERE id = %s",
        (uid,)).fetchone()
    assert row == (0, None), "a rule failure was counted as a sign-in attempt"
    # The same code still works, because nothing spent it.
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": creds.password, "totp_code": code,
        "new_password": "a sufficiently long one"})
    assert r.status_code == 204, r.text


def test_a_new_password_with_no_change_pending_is_refused_not_ignored(
        conn, client):
    from noctornal_api.security import passwords
    uid, email, secret = _make_user(conn)
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": _code(conn, uid, secret),
        "new_password": "something else entirely"})
    assert r.status_code == 409, r.text
    stored = conn.execute("SELECT password_hash FROM iam.app_user WHERE id = %s",
                          (uid,)).fetchone()[0]
    assert passwords.verify_password(stored, PASSWORD)
    assert _live_sessions(conn, uid) == 0


# --- Account: changing your own ---------------------------------------------

def test_a_person_changes_their_own_password_with_the_current_one_and_a_code(
        conn, client):
    from noctornal_api.security import passwords
    uid, email, secret = _make_user(conn)
    keep, token = _session(conn, uid)
    other, _ = _session(conn, uid)
    chosen = "a brand new passphrase"

    r = client.post("/api/v1/auth/password", headers=_auth(token), json={
        "current_password": PASSWORD, "totp_code": _code(conn, uid, secret),
        "new_password": chosen})
    assert r.status_code == 200, r.text
    assert r.json() == {"changed": True, "other_sessions_signed_out": 1}
    stored = conn.execute("SELECT password_hash FROM iam.app_user WHERE id = %s",
                          (uid,)).fetchone()[0]
    assert passwords.verify_password(stored, chosen)
    live = {r[0] for r in conn.execute(
        "SELECT id FROM iam.session WHERE user_id = %s AND revoked_at IS NULL",
        (uid,)).fetchall()}
    assert live == {keep}, "the change signed out the wrong sessions"
    assert other not in live
    [(_, detail)] = _audit(conn, uid, "PASSWORD_CHANGED")
    assert detail == {"via": "account", "sessions_revoked": 1}


def test_a_wrong_current_password_is_a_403_that_counts_toward_the_lockout(
        conn, client):
    from noctornal_api.security import passwords
    uid, email, secret = _make_user(conn)
    _, token = _session(conn, uid)
    r = client.post("/api/v1/auth/password", headers=_auth(token), json={
        "current_password": "not the password", "totp_code":
            _code(conn, uid, secret), "new_password": "a brand new passphrase"})
    assert r.status_code == 403, (
        "a 401 would tell the console the session had ended")
    assert "is not right" in r.json()["detail"]
    row = conn.execute(
        "SELECT password_hash, failed_logins FROM iam.app_user WHERE id = %s",
        (uid,)).fetchone()
    assert passwords.verify_password(row[0], PASSWORD)
    assert row[1] == 1, "a wrong current password did not count"
    assert conn.execute(
        """SELECT 1 FROM audit.event WHERE actor_id = %s
            AND action = 'PASSWORD_CHANGE_FAILED'""", (uid,)).fetchone()
    assert _live_sessions(conn, uid) == 1, "a refused change signed them out"


def test_the_account_change_needs_a_session(client):
    r = client.post("/api/v1/auth/password", json={
        "current_password": PASSWORD, "totp_code": "000000",
        "new_password": "a brand new passphrase"})
    assert r.status_code == 401


# --- the listing and the way in ----------------------------------------------

def test_the_listing_carries_the_flag_the_read_ins_and_last_activity(
        conn, client):
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    uid, _, _ = _make_user(conn)
    _svc(conn).register_compartment(key="PWR-ALPHA", label="Pwr alpha",
                                    actor_id=admin)
    _svc(conn).set_compartments(uid, ["PWR-ALPHA"], actor_id=admin)
    _svc(conn).reset_password(uid, actor_id=admin)
    _, token = _session(conn, admin)
    conn.execute("UPDATE iam.session SET last_seen_at = now() WHERE user_id = %s",
                 (admin,))

    users = {u["id"]: u for u in client.get(
        "/api/v1/admin/users", headers=_auth(token)).json()["users"]}
    mine = users[str(uid)]
    assert mine["must_change_password"] is True
    assert mine["compartments"] == ["PWR-ALPHA"]
    assert mine["password_changed_at"]
    assert mine["last_active_at"] is None
    assert users[str(admin)]["last_active_at"], (
        "an account in use through a minted session reads as never active")


def test_an_analyst_can_be_created_already_read_in(conn, client):
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    _svc(conn).register_compartment(key="PWR-BETA", label="Pwr beta",
                                    actor_id=admin)
    _, token = _session(conn, admin)
    email = f"pwr-{uuid4().hex[:8]}@noctornal.test"
    r = client.post("/api/v1/admin/users", headers=_auth(token), json={
        "email": email, "display_name": "Read in", "roles": ["ANALYST"],
        "compartments": ["PWR-BETA"]})
    assert r.status_code == 201, r.text
    held = conn.execute("SELECT compartments FROM iam.app_user WHERE email = %s",
                        (email,)).fetchone()[0]
    assert held == ["PWR-BETA"]

    missing = f"pwr-{uuid4().hex[:8]}@noctornal.test"
    r = client.post("/api/v1/admin/users", headers=_auth(token), json={
        "email": missing, "display_name": "Typo", "roles": ["ANALYST"],
        "compartments": ["PWR-NOPE"]})
    assert r.status_code == 409 and "PWR-NOPE" in r.json()["detail"]
    assert conn.execute("SELECT 1 FROM iam.app_user WHERE email = %s",
                        (missing,)).fetchone() is None, (
        "a refused read-in still created the account")


def test_the_way_in_tells_an_administrator_what_is_blocking(conn, client):
    from noctornal_api import readiness
    admin, _, _ = _make_user(conn, global_roles=("SYS_ADMIN",))
    analyst, _, _ = _make_user(conn)
    _, admin_token = _session(conn, admin, fresh=False)
    _, analyst_token = _session(conn, analyst)

    body = client.get("/api/v1/admin/access", headers=_auth(admin_token)).json()
    assert body["user_manage"] is True
    assert body["blocking_failures"] == readiness.blocking_failures(conn), (
        "the badge and the register disagree about what is blocking")
    # The officer check is the one probe that can pass with a caveat
    # (security-officer-false-green, 2026-09-23), and the answer says so
    # exactly when that probe does.
    lone = readiness._security_officer_present(conn).caveat
    assert body["readiness_caveats"] == (
        ["security_officer_present"] if lone else [])
    body = client.get("/api/v1/admin/access", headers=_auth(analyst_token)).json()
    assert body == {"user_manage": False, "break_glass_review": False,
                    "blocking_failures": [], "readiness_caveats": [],
                    # The two-person policy (F9).
                    "dual_control_manage": False,
                    "dual_control_countersign": False,
                    "dual_control_awaiting": 0,
                    # F12, the officer's YARA activations.
                    "sample_yara_activate": False,
                    # The collection authorities an officer confirms.
                    "collection_authority_confirm": False,
                    # S2, the Egress section's way in.
                    "egress_manage": False,
                    "egress_log_read": False,
                    # F6.3, the similarity indexes.
                    "embedding_manage": False,
                    # Integrations and Providers.
                    "integration_manage": False,
                    # F13, prohibited-content screening.
                    "sample_screening_review": False,
                    "sample_screening_manage": False}


# --- the shell ---------------------------------------------------------------

def test_bootstrap_reset_password_is_the_same_reset(conn, monkeypatch):
    import importlib.util
    from pathlib import Path

    from noctornal_api.security import passwords
    uid, email, _ = _make_user(conn)
    _session(conn, uid)
    script = Path(__file__).resolve().parents[3] / "scripts" / "bootstrap.py"
    monkeypatch.syspath_prepend(str(script.parent))
    spec = importlib.util.spec_from_file_location("bootstrap_under_test", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    out = io.StringIO()
    with redirect_stdout(out):
        assert module.main(["reset-password", "--email", email]) == 0
    printed = out.getvalue()
    assert "One-time password issued" in printed
    password = next(line.split()[-1] for line in printed.splitlines()
                    if line.strip().startswith("Password"))
    stored = conn.execute("SELECT password_hash FROM iam.app_user WHERE id = %s",
                          (uid,)).fetchone()[0]
    assert passwords.verify_password(stored, password)
    assert _flag(conn, uid) is True
    assert _live_sessions(conn, uid) == 0
    [(kind, detail)] = _audit(conn, uid, "PASSWORD_RESET")
    assert kind == "SYSTEM" and detail["via"] == "bootstrap.py"
