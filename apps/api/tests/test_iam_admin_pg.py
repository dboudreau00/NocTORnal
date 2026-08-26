"""Analyst account administration (`iam_admin.py`).

The tests that carry this file are the REFUSALS: the three ways an
administrator could lock the building — deactivating themselves,
deactivating the last SYS_ADMIN, removing the last SECURITY_OFFICER — and
the clearance change that would strand a case owner below their own case.
A green create path with broken guards is an admin panel that works right
up until it matters.

Env-gated on DATABASE_URL. NOCTORNAL_TOTP_KEK comes from conftest/env.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; admin tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "adm-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


def _svc(conn):
    from noctornal_api.iam_admin import IamAdminService
    return IamAdminService(conn)


def _mk(conn, *roles, active=True, clearance="AMBER"):
    creds = _svc(conn).create_analyst(
        email=f"adm-{uuid4().hex[:8]}@noctornal.test", display_name="A",
        clearance=clearance, roles=list(roles) or ["ANALYST"],
        actor_id=None)
    if not active:
        conn.execute(
            "UPDATE iam.app_user SET is_active = false WHERE id = %s",
            (creds.user_id,))
    return creds


# --- create ---------------------------------------------------------------

def test_create_provisions_everything_a_login_needs(conn):
    """User + clearance + roles + sealed TOTP in ONE transaction, exactly
    as bootstrap: a user who exists but cannot log in and cannot be
    re-created (the email is taken) is the worst partial state."""
    creds = _mk(conn, "ANALYST", "CASE_OWNER", clearance="RED")
    row = conn.execute(
        """SELECT tlp_clearance::text, totp_secret_ciphertext IS NOT NULL,
                  password_hash IS NOT NULL, is_active
             FROM iam.app_user WHERE id = %s""",
        (creds.user_id,)).fetchone()
    assert row == ("RED", True, True, True)
    roles = {r[0] for r in conn.execute(
        "SELECT role_key FROM iam.user_role WHERE user_id = %s",
        (creds.user_id,)).fetchall()}
    assert roles == {"ANALYST", "CASE_OWNER"}
    assert creds.password and creds.totp_secret
    assert creds.otpauth_uri.startswith("otpauth://totp/")


def test_a_duplicate_email_is_a_refusal_not_a_traceback(conn):
    from noctornal_api.iam_admin import AdminError
    creds = _mk(conn)
    with pytest.raises(AdminError, match="already exists"):
        _svc(conn).create_analyst(
            email=creds.email, display_name="B", clearance="AMBER",
            roles=["ANALYST"], actor_id=None)


def test_a_roleless_create_is_refused(conn):
    """A user with no global role can see nothing and fix nothing, and the
    email is then taken by an account that is pure liability."""
    from noctornal_api.iam_admin import AdminError
    with pytest.raises(AdminError, match="at least one global role"):
        _svc(conn).create_analyst(
            email=f"adm-{uuid4().hex[:8]}@noctornal.test", display_name="A",
            clearance="AMBER", roles=[], actor_id=None)


def test_creation_is_audited(conn):
    creds = _mk(conn)
    row = conn.execute(
        """SELECT action FROM audit.event
            WHERE object_id = %s AND action = 'USER_CREATED'""",
        (creds.user_id,)).fetchone()
    assert row is not None


# --- the three refusals ---------------------------------------------------

def test_you_cannot_deactivate_yourself(conn):
    from noctornal_api.iam_admin import AdminError
    me = _mk(conn, "SYS_ADMIN")
    other = _mk(conn, "SYS_ADMIN")  # so "last admin" is not the refusal
    assert other
    with pytest.raises(AdminError, match="your own account"):
        _svc(conn).set_active(me.user_id, active=False, actor_id=me.user_id)


def test_the_last_active_sys_admin_cannot_be_deactivated(conn):
    """A deployment with zero user-managers can only be repaired from the
    database shell, which is the situation this module exists to end.

    The state is created and then ROLLED BACK rather than skipped: this
    database has other SYS_ADMINs, and the first version of this test
    skipped when it did — but CI fails the build on any skip at all, and
    a guard that only runs on an empty database is a guard nobody runs.
    Deactivating the others inside a transaction and raising
    `psycopg.Rollback` exercises the real code path and leaves not one
    row changed.
    """
    import psycopg

    from noctornal_api.iam_admin import AdminError
    actor = _mk(conn, "SECURITY_OFFICER")
    target = _mk(conn, "SYS_ADMIN")
    try:
        with conn.transaction():
            conn.execute(
                """UPDATE iam.app_user SET is_active = false
                    WHERE id <> %s AND id IN (
                      SELECT user_id FROM iam.user_role
                       WHERE role_key = 'SYS_ADMIN')""",
                (target.user_id,))
            with pytest.raises(AdminError, match="last active SYS_ADMIN"):
                _svc(conn).set_active(target.user_id, active=False,
                                      actor_id=actor.user_id)
            raise psycopg.Rollback
    except psycopg.Rollback:
        pass
    # Nothing outside the fixture's own users was touched.
    still_active = conn.execute(
        """SELECT count(*) FROM iam.user_role ur
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.role_key = 'SYS_ADMIN' AND u.is_active""").fetchone()[0]
    assert still_active >= 1, "the rollback did not restore the census"


def test_two_concurrent_deactivations_cannot_zero_the_admins(conn):
    """The guard was an unlocked check-then-write: two admins deactivating
    the last two SYS_ADMINs at the same instant each saw the other still
    active, each passed, and the deployment landed with none.

    `_lock_role_census` now serialises the check and the write in one
    transaction. This asserts the lock is actually taken — a second
    connection must BLOCK while the first holds it mid-guard.
    """
    import psycopg

    from noctornal_api.db import dsn
    other = psycopg.connect(dsn())
    try:
        with conn.transaction():
            _svc(conn)._lock_role_census()
            other.execute("SET statement_timeout = '1200ms'")
            with pytest.raises(psycopg.errors.QueryCanceled):
                other.execute(
                    "SELECT pg_advisory_xact_lock("
                    "  hashtextextended('iam.role_census', 0))")
    finally:
        other.rollback()
        other.close()


def test_revoking_the_last_officer_role_is_refused_when_last(conn):
    """Break-glass refuses to grant when nobody can review it, so removing
    the last SECURITY_OFFICER quietly disables emergency access. On a
    populated database the guard is exercised via count: revoking from a
    user who is NOT the last holder must succeed."""
    officer = _mk(conn, "SECURITY_OFFICER", "ANALYST")
    others = conn.execute(
        """SELECT count(*) FROM iam.user_role ur
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active
              AND ur.user_id <> %s""", (officer.user_id,)).fetchone()[0]
    svc = _svc(conn)
    if others == 0:
        from noctornal_api.iam_admin import AdminError
        with pytest.raises(AdminError, match="SECURITY_OFFICER"):
            svc.revoke_role(officer.user_id, role="SECURITY_OFFICER",
                            actor_id=officer.user_id)
    else:
        svc.revoke_role(officer.user_id, role="SECURITY_OFFICER",
                        actor_id=officer.user_id)
        left = {r[0] for r in conn.execute(
            "SELECT role_key FROM iam.user_role WHERE user_id = %s",
            (officer.user_id,)).fetchall()}
        assert "SECURITY_OFFICER" not in left


def test_deactivation_revokes_every_live_session(conn):
    """A deactivated account with a live session is not deactivated."""
    from noctornal_api.security.sessions import SessionService
    admin = _mk(conn, "SYS_ADMIN")
    target = _mk(conn, "ANALYST")
    conn.execute(
        """INSERT INTO iam.session
               (id, user_id, token_hash, issued_at, expires_at,
                mfa_satisfied_at)
           VALUES (%s, %s, %s, now(), now() + interval '8 hours', now())""",
        (uuid4(), target.user_id, os.urandom(32)))
    _svc(conn).set_active(target.user_id, active=False,
                          actor_id=admin.user_id)
    live = conn.execute(
        """SELECT count(*) FROM iam.session
            WHERE user_id = %s AND revoked_at IS NULL""",
        (target.user_id,)).fetchone()[0]
    assert live == 0, "the account is deactivated and still signed in"
    assert SessionService  # imported to fail loudly if the module moves


# --- clearance ------------------------------------------------------------

def test_lowering_clearance_below_an_owned_case_is_refused(conn):
    """The mirror of the raise cases.py refuses: both make an owner who
    cannot read their own case, and there is no route back."""
    from noctornal_api.cases import CaseService
    from noctornal_api.iam_admin import AdminError
    admin = _mk(conn, "SYS_ADMIN")
    owner = _mk(conn, "CASE_OWNER", clearance="RED")
    future = date.today() + timedelta(days=365)
    CaseService(conn).create(
        code=f"OP-ADM-{uuid4().hex[:6]}", title="Admin guard",
        legal_basis="dev", retention_until=future,
        review_due=future - timedelta(days=30),
        owner_user_id=owner.user_id, created_by=owner.user_id,
        classification="RED")
    with pytest.raises(AdminError, match="strand"):
        _svc(conn).set_clearance(owner.user_id, clearance="GREEN",
                                 actor_id=admin.user_id)
    # Raising, and lowering above the case, both fine.
    _svc(conn).set_clearance(owner.user_id, clearance="RED",
                             actor_id=admin.user_id)


# --- credentials ----------------------------------------------------------

def test_reenrol_issues_a_different_secret_and_audits(conn):
    admin = _mk(conn, "SYS_ADMIN")
    target = _mk(conn, "ANALYST")
    first = target.totp_secret
    second = _svc(conn).reenrol_totp(target.user_id, actor_id=admin.user_id)
    assert second.totp_secret and second.totp_secret != first
    assert conn.execute(
        """SELECT 1 FROM audit.event
            WHERE object_id = %s AND action = 'TOTP_REENROLLED'""",
        (target.user_id,)).fetchone() is not None


def test_unlock_clears_the_lockout(conn):
    admin = _mk(conn, "SYS_ADMIN")
    target = _mk(conn, "ANALYST")
    conn.execute(
        """UPDATE iam.app_user
              SET failed_logins = 7, locked_until = now() + interval '1 hour'
            WHERE id = %s""", (target.user_id,))
    _svc(conn).unlock(target.user_id, actor_id=admin.user_id)
    row = conn.execute(
        "SELECT failed_logins, locked_until FROM iam.app_user WHERE id = %s",
        (target.user_id,)).fetchone()
    assert row == (0, None)


# --- first run ------------------------------------------------------------

def test_first_run_is_closed_on_a_populated_deployment(conn):
    """The door exists only while iam.app_user is EMPTY — active or not.
    This database has users, so the only reachable branch here is the
    refusal; the open-door path runs on CI, whose database is fresh."""
    from noctornal_api.iam_admin import AdminError, create_first_admin, needs_setup
    if needs_setup(conn):
        creds = create_first_admin(conn, email="adm-first@noctornal.test",
                                   display_name="First")
        roles = {r[0] for r in conn.execute(
            "SELECT role_key FROM iam.user_role WHERE user_id = %s",
            (creds.user_id,)).fetchall()}
        assert {"SYS_ADMIN", "SECURITY_OFFICER"} <= roles
    else:
        with pytest.raises(AdminError, match="already has accounts"):
            create_first_admin(conn, email="adm-x@noctornal.test",
                               display_name="X")


# ---------------------------------------------------------------------------
# From the 2026-08-25 hostile pass over this surface
# ---------------------------------------------------------------------------

def test_a_deputy_is_not_stranded_either(conn):
    """The first version checked owners only. `cases.py` checks a DEPUTY's
    clearance at creation for the same reason it checks the owner's: a
    deputy exists to act when the owner cannot, so a deputy who cannot
    open the case is a succession plan that fails on the day it is
    needed — silently, with a bare 200."""
    from noctornal_api.cases import CaseService
    from noctornal_api.iam_admin import AdminError
    admin = _mk(conn, "SYS_ADMIN")
    owner = _mk(conn, "CASE_OWNER", clearance="RED")
    deputy = _mk(conn, "ANALYST", clearance="RED")
    future = date.today() + timedelta(days=365)
    CaseService(conn).create(
        code=f"OP-ADM-{uuid4().hex[:6]}", title="Deputy guard",
        legal_basis="dev", retention_until=future,
        review_due=future - timedelta(days=30),
        owner_user_id=owner.user_id, created_by=owner.user_id,
        deputy_user_id=deputy.user_id, classification="RED")
    with pytest.raises(AdminError, match="deputy"):
        _svc(conn).set_clearance(deputy.user_id, clearance="GREEN",
                                 actor_id=admin.user_id)


def test_role_changes_on_a_nonexistent_user_are_refused_not_faked(conn):
    """Grant let a raw ForeignKeyViolation reach the catch-all as
    "Internal error: unexpected failure"; revoke deleted nothing and
    answered 200 "revoked" — a no-op reported as a completed authz
    change, which is the worse of the two."""
    from noctornal_api.iam_admin import AdminError
    admin = _mk(conn, "SYS_ADMIN")
    ghost = uuid4()
    with pytest.raises(AdminError, match="no such user"):
        _svc(conn).grant_role(ghost, role="ANALYST", actor_id=admin.user_id)
    with pytest.raises(AdminError, match="no such user"):
        _svc(conn).revoke_role(ghost, role="ANALYST", actor_id=admin.user_id)


def test_reenrolling_totp_evicts_the_stolen_device(conn):
    """The scenario IS a lost phone. A new secret alone does not evict
    whoever holds the old one: an existing session carries its own token
    and never re-presents TOTP, so the panel's promise that the old
    authenticator "stops working immediately" was false for exactly the
    person it was protecting against."""
    admin = _mk(conn, "SYS_ADMIN")
    target = _mk(conn, "ANALYST")
    conn.execute(
        """INSERT INTO iam.session
               (id, user_id, token_hash, issued_at, expires_at,
                mfa_satisfied_at)
           VALUES (%s, %s, %s, now(), now() + interval '8 hours', now())""",
        (uuid4(), target.user_id, os.urandom(32)))
    _svc(conn).reenrol_totp(target.user_id, actor_id=admin.user_id)
    live = conn.execute(
        """SELECT count(*) FROM iam.session
            WHERE user_id = %s AND revoked_at IS NULL""",
        (target.user_id,)).fetchone()[0]
    assert live == 0, "the stolen device still holds a valid session"


def test_the_collection_roles_are_grantable_from_the_panel(conn):
    """The seed carries eleven roles; the allowlist carried six, so a
    deployment could not staff its own collection surface without a shell
    on the server — the hurdle this module exists to remove."""
    from noctornal_api.iam_admin import GRANTABLE_ROLES
    seeded = {r[0] for r in conn.execute(
        "SELECT key FROM iam.role").fetchall()}
    assert "COLLECTOR" in GRANTABLE_ROLES
    assert GRANTABLE_ROLES <= seeded, (
        "the allowlist names a role this deployment's seed does not have")
    # SERVICE is a machine identity and stays out on purpose.
    assert "SERVICE" not in GRANTABLE_ROLES
