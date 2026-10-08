"""The request role cannot write what decides who it is (S1, 2026-09-25).

The policies read the IAM plane and lab.download_ticket, so a request
role that could write them could rebind itself as anyone (a forged
session row, a rewritten binding hash) or widen its own reach (its
clearance, a role, an assignment, a grant). 0109 makes them read-only to
the request role; 0112 confines the two column grants that remained, and
0180 took the ticket's back (a ticket is spent through its definer). Each
forging write below is attempted as SET ROLE noctornal_app, bound as an
ordinary analyst, and must be refused.
"""
from __future__ import annotations

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c)
    c.close()


@pytest.fixture
def people(owner):
    analyst = s.user(owner, "AMBER")
    admin = s.user(owner, "RED")
    case_id = s.case(owner, admin)
    s.assign(owner, case_id, analyst)
    sid, raw = s.session(owner, analyst)
    admin_sid, _ = s.session(owner, admin)
    return {"analyst": analyst, "admin": admin, "case": case_id, "sid": sid,
            "raw": raw, "admin_sid": admin_sid}


FORGERIES = {
    "session_insert": (
        "INSERT INTO iam.session (user_id, token_hash, expires_at, rls_binding_hash) "
        "VALUES (%(admin)s, '\\x00', now() + interval '1 hour', '\\x01')"),
    "binding_rewrite": (
        "UPDATE iam.session SET rls_binding_hash = '\\x01' WHERE id = %(admin_sid)s"),
    "session_owner_rewrite": (
        "UPDATE iam.session SET user_id = %(admin)s WHERE id = %(sid)s"),
    "session_expiry_extended": (
        "UPDATE iam.session SET expires_at = now() + interval '30 days' WHERE id = %(sid)s"),
    "clearance_raised": (
        "UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %(analyst)s"),
    "compartments_widened": (
        "UPDATE iam.app_user SET compartments = '{}' WHERE id = %(analyst)s"),
    "password_replaced": (
        "UPDATE iam.app_user SET password_hash = 'x' WHERE id = %(admin)s"),
    "role_granted": (
        "INSERT INTO iam.user_role (user_id, role_key) VALUES (%(analyst)s, 'SECURITY_OFFICER')"),
    "assignment_forged": (
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by) "
        "VALUES (%(case)s, %(admin)s, 'ANALYST', %(analyst)s)"),
    "grant_forged": (
        "INSERT INTO iam.break_glass (user_id, justification, expires_at, "
        "granted_classification) VALUES (%(analyst)s, 'a forged emergency of some length', "
        "now() + interval '1 hour', 'RED')"),
    "verb_granted": (
        "INSERT INTO iam.role_permission (role_key, permission_key) "
        "VALUES ('ANALYST', 'audit.read')"),
    "compartment_registered": (
        "INSERT INTO iam.compartment (key, label) VALUES ('RLS-FORGED', 'forged')"),
    "ticket_forged": (
        "INSERT INTO lab.download_ticket (token_hash, evidence_id, user_id, expires_at, "
        "purpose, redeemed_at) VALUES ('\\x02', gen_random_uuid(), %(admin)s, "
        "now() + interval '1 minute', 'exhibit_production', now())"),
}


@pytest.mark.parametrize("name", sorted(FORGERIES))
def test_every_forging_write_is_refused_to_the_request_role(owner, people, name):
    app = s.app_conn(people["raw"])
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(FORGERIES[name], people)
    finally:
        app.close()


def test_the_request_role_keeps_its_own_session_activity_and_nothing_else(owner, people):
    """Touch and logout still work on the bound session; the same columns
    on anybody else's session are refused by 0112's guard, and a revoked
    session stays revoked. Stamping step-up is no longer the request
    role's to do (0144, rls-7 2026-10-03): it is a sign-in's."""
    # the idle window only slides forward (0144), and the fixture stamps the
    # session from the test host's clock, which can sit ahead of the database's:
    # put the stamp in the database's past first
    owner.execute("UPDATE iam.session SET last_seen_at = now() - interval '1 minute' "
                  "WHERE id IN (%s, %s)", (people["sid"], people["admin_sid"]))
    app = s.app_conn(people["raw"])
    try:
        cur = app.execute("UPDATE iam.session SET last_seen_at = now() "
                          "WHERE id = %s", (people["sid"],))
        assert cur.rowcount == 1
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE iam.session SET mfa_satisfied_at = now() "
                        "WHERE id = %s", (people["sid"],))
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="bound to"):
            app.execute("UPDATE iam.session SET last_seen_at = now() WHERE id = %s",
                        (people["admin_sid"],))
        app.execute("UPDATE iam.session SET revoked_at = now(), revoke_reason = 'logout' "
                    "WHERE id = %s", (people["sid"],))
    finally:
        app.close()
    # Revoked: the proof binds nobody now, so a fresh connection holds no
    # binding and the guard refuses the un-revoke as not its session.
    app = s.app_conn(people["raw"])
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE iam.session SET revoked_at = NULL WHERE id = %s",
                        (people["sid"],))
    finally:
        app.close()


def test_a_ticket_is_spent_once_by_the_request_role_and_never_written_by_it(owner, people):
    """Since 0180 the request role spends a ticket only through its definer,
    by the hash of the ticket it holds, once; it writes no ticket column,
    so a spent ticket is never unspent and never given to somebody else."""
    exhibit = s.exhibit(owner, people["case"], people["admin"])
    digest = s.os.urandom(32)
    ticket = owner.execute(
        """INSERT INTO lab.download_ticket (token_hash, evidence_id, user_id, expires_at,
                                            purpose)
           VALUES (%s, %s, %s, now() + interval '1 minute', 'exhibit_production')
           RETURNING id""", (digest, exhibit, people["analyst"])).fetchone()[0]
    spend = ("SELECT id FROM lab.spend_production_ticket(%s, %s, 'exhibit_production', %s)")
    app = s.app_conn()
    try:
        assert app.execute(spend, (digest, exhibit, people["case"])).fetchall() == [(ticket,)]
        assert app.execute(spend, (digest, exhibit, people["case"])).fetchall() == []
        for sql, params in (
                ("UPDATE lab.download_ticket SET redeemed_at = NULL WHERE id = %s", (ticket,)),
                ("UPDATE lab.download_ticket SET redeemed_at = now() WHERE id = %s",
                 (ticket,)),
                ("UPDATE lab.download_ticket SET user_id = %s WHERE id = %s",
                 (people["admin"], ticket))):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(sql, params)
    finally:
        app.close()
        owner.execute("DELETE FROM lab.download_ticket WHERE id = %s", (ticket,))


def test_a_break_glass_use_counts_only_the_bound_actors_own_live_grant(owner, people):
    mine = s.break_glass(owner, people["analyst"], "RED", people["case"])
    theirs = s.break_glass(owner, people["admin"], "RED")
    app = s.app_conn(people["raw"])
    try:
        assert app.execute("SELECT iam.rls_record_break_glass_use(%s)",
                           (mine,)).fetchone()[0] is True
        assert app.execute("SELECT iam.rls_record_break_glass_use(%s)",
                           (theirs,)).fetchone()[0] is False
    finally:
        app.close()
    counts = dict(owner.execute(
        "SELECT id, action_count FROM iam.break_glass WHERE id = ANY(%s)",
        ([mine, theirs],)).fetchall())
    assert counts == {mine: 1, theirs: 0}
    # The owner (and the system role) count as the old UPDATE did.
    assert owner.execute("SELECT iam.rls_record_break_glass_use(%s)",
                         (theirs,)).fetchone()[0] is True
