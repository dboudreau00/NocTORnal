"""The session plane after the 2026-10-03 review (g45): a dead session stays
dead, and the request role cannot read credentials, forge step-up freshness
or write a notification as somebody else.

- authz-session-revoke-bypass: `current_user` read a session, then slid its
  idle window by rewriting the WHOLE row from what it had read, so a logout,
  a password change, a deactivation or a TOTP re-enrolment committed in the
  gap was written back to NULL and the token kept working.
- rls-6: the request role could SELECT every account's password hash, TOTP
  ciphertext and recovery hashes (0143).
- rls-7: the request role could stamp `mfa_satisfied_at` on its own session
  and push `last_seen_at` into the future (0144).
- rls-8: `notify.enqueue` ran for an unbound caller, stored a caller-supplied
  actor and wrote any delivery state (0145).

Every assertion that a refusal happens is paired with one that the
legitimate act still works, because a fix that closes the door for everyone
is not a fix. Accounts carry the prefix `g45ses-`, unique to this file.
"""
from __future__ import annotations

import importlib.util
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "g45ses-"
MIGRATIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"

#: A notice a request raises, in the product's own words: since 0181 a
#: request-role caller raises only those (test_notify_templates_pg.py).
ENQUEUE = ("SELECT outcome, raised_id FROM notify.enqueue("
           "%s::uuid, NULL, 'APPROVAL_DECIDED', 2::smallint, "
           "'Your request was countersigned: Change a role definition', "
           "'Your deployment-wide request was countersigned.', "
           "'body text', 'CLEAR'::core.tlp, '{}'::text[], NULL, NULL, %s::uuid, NULL, "
           "%s::jsonb, NULL)")


def _migration(number: str):
    path = next(MIGRATIONS.glob(f"{number}_*.py"))
    spec = importlib.util.spec_from_file_location(f"g45m{number}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c, prefix=PREFIX)
    c.close()


def _service(conn):
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    return SessionService(PgSessionStore(conn))


def _row(conn, sid: UUID):
    return conn.execute(
        "SELECT revoked_at, revoke_reason, mfa_satisfied_at, last_seen_at "
        "FROM iam.session WHERE id = %s", (sid,)).fetchone()


# ---------------------------------------------------------------------------
# authz-session-revoke-bypass
# ---------------------------------------------------------------------------

def test_a_touch_after_a_concurrent_revocation_refuses_and_never_unrevokes(owner):
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid)
    reader = s.owner_conn()
    try:
        stale = _service(reader).validate(raw, touch=False).session
        assert stale is not None and stale.revoked_at is None
        # The other connection's logout, password change or deactivation.
        assert _service(owner).revoke_all_for_user(uid, "password changed") == 1
        assert _service(reader).touch(stale) is None
    finally:
        reader.close()
    revoked_at, reason, _mfa, _seen = _row(owner, sid)
    assert revoked_at is not None and reason == "password changed"
    assert not _service(owner).validate(raw).ok


def test_a_touch_never_wakes_an_idle_or_expired_session(owner):
    uid = s.user(owner, prefix=PREFIX)
    idle_sid, idle_raw = s.session(owner, uid)
    gone_sid, gone_raw = s.session(owner, uid)
    owner.execute("UPDATE iam.session SET last_seen_at = now() - interval '31 minutes' "
                  "WHERE id = %s", (idle_sid,))
    owner.execute("UPDATE iam.session SET expires_at = now() - interval '1 minute' "
                  "WHERE id = %s", (gone_sid,))
    before = (_row(owner, idle_sid)[3], _row(owner, gone_sid)[3])
    svc = _service(owner)
    for raw in (idle_raw, gone_raw):
        record = svc.validate(raw, touch=False)
        assert not record.ok
    from noctornal_api.stores import PgSessionStore
    store = PgSessionStore(owner)
    now = datetime.now(timezone.utc)
    for sid in (idle_sid, gone_sid):
        assert store.slide(sid, now, now - timedelta(minutes=30)) is None
    assert (_row(owner, idle_sid)[3], _row(owner, gone_sid)[3]) == before


def test_the_slide_writes_the_idle_window_and_nothing_else(owner):
    """The old whole-row update restored every column from the record the
    caller held, so it also undid a second factor recorded or cleared in
    between. The slide names last_seen_at alone."""
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid, mfa=True)
    stale = _service(owner).validate(raw, touch=False).session
    assert stale.mfa_satisfied_at is not None
    owner.execute("UPDATE iam.session SET mfa_satisfied_at = NULL, "
                  "last_seen_at = now() - interval '10 minutes' WHERE id = %s", (sid,))
    touched = _service(owner).touch(stale)
    assert touched is not None
    revoked_at, _reason, mfa_at, seen = _row(owner, sid)
    assert mfa_at is None, "a stale record restored a column the slide does not own"
    assert revoked_at is None
    assert seen > datetime.now(timezone.utc) - timedelta(minutes=1)
    assert touched.last_seen_at == seen


def test_two_overlapping_slides_never_move_the_window_backwards(owner):
    uid = s.user(owner, prefix=PREFIX)
    sid, _raw = s.session(owner, uid)
    from noctornal_api.stores import PgSessionStore
    store = PgSessionStore(owner)
    now = datetime.now(timezone.utc)
    floor = now - timedelta(minutes=30)
    later = store.slide(sid, now, floor)
    earlier = store.slide(sid, now - timedelta(seconds=20), floor)
    assert earlier == later, "a slower request moved last_seen_at backwards"


@pytest.mark.parametrize("assume_role", [False, True], ids=["owner", "request_role"])
def test_a_request_racing_a_revocation_is_refused_and_the_session_stays_dead(
        owner, monkeypatch, assume_role):
    """The interleaving, made deterministic: the revocation commits after the
    session was read AND the connection bound, which is the last moment
    before the slide (an earlier one is caught by the bind in the request
    role, and by nothing at all on an owner connection, which binds to
    nothing). Owner posture is where the session came back to life;
    request-role posture is production, where 0112's guard turned the same
    race into a 500 on the attacker's one in-flight request. Both are a
    clean 401 now."""
    from fastapi.testclient import TestClient

    from noctornal_api.http import deps
    from noctornal_api.http.app import create_app
    if assume_role:
        monkeypatch.setenv("NOCTORNAL_TEST_ASSUME_ROLE", "1")
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid)
    real = deps.refuse_unbindable_session

    def racing(conn, session, token):
        real(conn, session, token)
        other = s.owner_conn()
        try:
            _service(other).revoke_all_for_user(uid, "password changed")
        finally:
            other.close()

    monkeypatch.setattr(deps, "refuse_unbindable_session", racing)
    client = TestClient(create_app(), raise_server_exceptions=False)
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 401, (r.status_code, r.text)
    monkeypatch.setattr(deps, "refuse_unbindable_session", real)
    revoked_at, reason, _m, _seen = _row(owner, sid)
    assert revoked_at is not None and reason == "password changed"
    again = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}"})
    assert again.status_code == 401


def test_the_websocket_gate_refuses_a_session_revoked_between_its_read_and_its_slide(
        owner, monkeypatch):
    from noctornal_api.http.routers import live
    from noctornal_api.security.sessions import SessionService
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid)
    real = SessionService.validate

    def racing(self, token, *, touch=True):
        result = real(self, token, touch=touch)
        if result.ok and touch is False:
            other = s.owner_conn()
            try:
                _service(other).revoke_all_for_user(uid, "deactivated")
            finally:
                other.close()
        return result

    monkeypatch.setattr(SessionService, "validate", racing)
    assert live._authenticate(raw, None, None, None) is None
    monkeypatch.setattr(SessionService, "validate", real)
    assert _row(owner, sid)[0] is not None


def test_an_ordinary_request_still_slides_the_window_and_logout_still_revokes(
        owner, monkeypatch):
    """The other direction, in the production posture: nothing legitimate
    was taken away."""
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    monkeypatch.setenv("NOCTORNAL_TEST_ASSUME_ROLE", "1")
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid)
    owner.execute("UPDATE iam.session SET last_seen_at = now() - interval '10 minutes' "
                  "WHERE id = %s", (sid,))
    client = TestClient(create_app(), raise_server_exceptions=False)
    headers = {"Authorization": f"Bearer {raw}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    assert _row(owner, sid)[3] > datetime.now(timezone.utc) - timedelta(minutes=1)
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    assert _row(owner, sid)[0] is not None
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


# ---------------------------------------------------------------------------
# rls-6: credential columns
# ---------------------------------------------------------------------------

def test_the_request_role_holds_no_privilege_on_a_credential_column(owner):
    m = _migration("0143")
    for column in m.CREDENTIAL_COLUMNS:
        assert owner.execute(
            "SELECT has_column_privilege(%s, 'iam.app_user', %s, 'SELECT')",
            (s.APP_ROLE, column)).fetchone()[0] is False, column
    assert owner.execute("SELECT has_table_privilege(%s, 'iam.app_user', 'SELECT')",
                         (s.APP_ROLE,)).fetchone()[0] is False
    # Every other column is still readable. The columns are discovered from
    # the catalog when the revision runs, not listed in it, so a column a
    # sibling revision added before it is granted too.
    every = {r[0] for r in owner.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'iam' AND table_name = 'app_user'")}
    assert set(m.CREDENTIAL_COLUMNS) <= every
    assert {"id", "email", "display_name", "is_active", "tlp_clearance",
            "compartments", "must_change_password"} <= every - set(m.CREDENTIAL_COLUMNS)
    for column in every - set(m.CREDENTIAL_COLUMNS):
        assert owner.execute(
            "SELECT has_column_privilege(%s, 'iam.app_user', %s, 'SELECT')",
            (s.APP_ROLE, column)).fetchone()[0] is True, column


@pytest.mark.parametrize("bound", [False, True], ids=["unbound", "bound"])
def test_a_request_role_connection_cannot_read_a_credential(owner, bound):
    """The review's reproduction: an unbound request-role connection read
    every account's hash, sealed TOTP secret and recovery hashes. Bound or
    not, each is now refused, and so is a `SELECT *`."""
    m = _migration("0143")
    uid = s.user(owner, prefix=PREFIX)
    _sid, raw = s.session(owner, uid)
    app = s.app_conn(raw if bound else None)
    try:
        for column in m.CREDENTIAL_COLUMNS:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(f"SELECT {column} FROM iam.app_user")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM iam.app_user")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT count(*) FROM iam.app_user WHERE password_hash IS NOT NULL")
        # The columns the request path reads are untouched.
        n = app.execute("SELECT count(email), count(tlp_clearance), count(display_name) "
                        "FROM iam.app_user").fetchone()
        assert n[0] >= 1 and n[1] >= 1 and n[2] >= 1
    finally:
        app.close()


def test_the_system_role_still_reads_the_credentials_sign_in_needs(owner):
    """Sign-in, second factors and recovery codes run on a system connection
    (the worker role); the revoke is the request role's alone."""
    uid = s.user(owner, prefix=PREFIX)
    from noctornal_api.db import connect
    worker = connect()
    try:
        worker.execute(f"SET ROLE {s.WORKER_ROLE}")
        row = worker.execute(
            "SELECT password_hash, totp_secret_ciphertext, recovery_codes_hash, "
            "totp_last_counter, totp_key_id FROM iam.app_user WHERE id = %s",
            (uid,)).fetchone()
        assert row[0] and str(row[0]).startswith("$")
    finally:
        worker.close()


def test_recovery_codes_remaining_answers_only_for_the_bound_account(owner):
    from noctornal_api.stores import PgUserStore
    me = s.user(owner, prefix=PREFIX)
    other = s.user(owner, prefix=PREFIX)
    PgUserStore(owner).issue_recovery_codes(me, count=7)
    PgUserStore(owner).issue_recovery_codes(other, count=3)
    _sid, raw = s.session(owner, me)
    app = s.app_conn(raw)
    unbound = s.app_conn(None)
    try:
        assert PgUserStore(app).recovery_codes_remaining(me) == 7
        # Anybody else's count is the answer an account that does not exist gets.
        assert PgUserStore(app).recovery_codes_remaining(other) is None
        assert PgUserStore(app).recovery_codes_remaining(uuid4()) is None
        assert PgUserStore(unbound).recovery_codes_remaining(me) is None
    finally:
        app.close()
        unbound.close()
    # An exempt caller (the owner in development, the system role) may ask.
    assert PgUserStore(owner).recovery_codes_remaining(other) == 3
    acl = owner.execute(
        "SELECT coalesce(proacl::text, '') FROM pg_proc "
        "WHERE oid = 'iam.recovery_codes_remaining(uuid)'::regprocedure").fetchone()[0]
    assert not re.search(r"(^|[{,])=X/", acl), "EXECUTE is still granted to PUBLIC"
    for role in (s.APP_ROLE, s.WORKER_ROLE):
        assert owner.execute(
            "SELECT has_function_privilege(%s, 'iam.recovery_codes_remaining(uuid)', "
            "'EXECUTE')", (role,)).fetchone()[0] is True


def test_me_still_reports_the_recovery_code_count_in_the_production_posture(
        owner, monkeypatch):
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.stores import PgUserStore
    monkeypatch.setenv("NOCTORNAL_TEST_ASSUME_ROLE", "1")
    uid = s.user(owner, prefix=PREFIX)
    PgUserStore(owner).issue_recovery_codes(uid, count=5)
    _sid, raw = s.session(owner, uid)
    r = TestClient(create_app(), raise_server_exceptions=False).get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 200, r.text
    assert r.json()["recovery_codes_remaining"] == 5


def test_the_migration_replays_cleanly_through_the_runtime_roles_script(owner):
    """`scripts/runtime_roles.py ensure` replays 0108's table grants and then
    the two revisions that take columns back; run again it must leave the
    same state (idempotent)."""
    m = _migration("0143")
    owner.execute(m.PRIVILEGES_SQL)
    owner.execute(m.PRIVILEGES_SQL)
    assert owner.execute("SELECT has_column_privilege(%s, 'iam.app_user', "
                         "'password_hash', 'SELECT')", (s.APP_ROLE,)).fetchone()[0] is False
    n = _migration("0144")
    owner.execute(n.PRIVILEGES_SQL)
    owner.execute(n.PRIVILEGES_SQL)
    assert owner.execute("SELECT has_column_privilege(%s, 'iam.session', "
                         "'mfa_satisfied_at', 'UPDATE')", (s.APP_ROLE,)).fetchone()[0] is False


# ---------------------------------------------------------------------------
# rls-7: step-up freshness and the idle window
# ---------------------------------------------------------------------------

def test_the_request_role_cannot_stamp_step_up_on_its_own_session(owner):
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid, mfa=False)
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE iam.session SET mfa_satisfied_at = now() WHERE id = %s",
                        (sid,))
    finally:
        app.close()
    assert _row(owner, sid)[2] is None
    from noctornal_api.security.sessions import SessionService
    record = _service(owner).validate(raw, touch=False).session
    assert not _service(owner).is_step_up_fresh(record)
    assert not hasattr(SessionService, "mark_mfa_satisfied")


def test_the_guard_refuses_the_values_a_column_grant_would_allow(owner):
    """The column grant is the first wall; the trigger is the second, and is
    exercised here with the grant put back inside a transaction that is
    rolled back, so a later revision that re-grants the column cannot
    quietly reopen the hole."""
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid, mfa=False)
    from noctornal_api.db import bind_session, connect
    c = connect()
    try:
        with c.transaction(force_rollback=True):
            c.execute(f"GRANT UPDATE (mfa_satisfied_at) ON iam.session TO {s.APP_ROLE}")
            c.execute(f"SET ROLE {s.APP_ROLE}")
            bind_session(c, raw)

            def refused(sql: str, fragment: str) -> None:
                c.execute("SAVEPOINT g")
                with pytest.raises(psycopg.errors.InsufficientPrivilege, match=fragment):
                    c.execute(sql, (sid,))
                c.execute("ROLLBACK TO SAVEPOINT g")

            refused("UPDATE iam.session SET mfa_satisfied_at = now() WHERE id = %s",
                    "second factor is recorded only at sign-in")
            refused("UPDATE iam.session SET last_seen_at = '9999-01-01' WHERE id = %s",
                    "only slides forward")
            refused("UPDATE iam.session SET last_seen_at = now() + interval '10 minutes' "
                    "WHERE id = %s", "only slides forward")
            refused("UPDATE iam.session SET last_seen_at = now() - interval '1 hour' "
                    "WHERE id = %s", "only slides forward")
            refused("UPDATE iam.session SET last_seen_at = NULL WHERE id = %s",
                    "only slides forward")
            # The slide the application makes, with the API clock a little
            # ahead, is inside the allowance.
            ok = c.execute("UPDATE iam.session SET last_seen_at = now() + interval '2 minutes' "
                           "WHERE id = %s", (sid,))
            assert ok.rowcount == 1
    finally:
        c.close()


def test_the_slide_survives_a_fast_api_clock_in_the_production_posture(owner):
    """The guard allows five minutes of skew; the store clamps what it
    writes to the database's clock plus one minute, so an API host whose
    clock runs ahead cannot turn every request into a refusal."""
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid)
    from noctornal_api.db import bind_session, connect
    from noctornal_api.stores import PgSessionStore
    c = connect()
    try:
        c.execute(f"SET ROLE {s.APP_ROLE}")
        bind_session(c, raw)
        far_ahead = datetime.now(timezone.utc) + timedelta(hours=2)
        seen = PgSessionStore(c).slide(sid, far_ahead, far_ahead - timedelta(hours=3))
        assert seen is not None
        assert seen <= datetime.now(timezone.utc) + timedelta(minutes=2)
    finally:
        c.close()


def test_a_form_sign_in_still_records_the_second_factor_when_it_mints(owner):
    """Step-up is minted fresh on the system connection, with the stamp
    already set; the request role never writes it."""
    uid = s.user(owner, prefix=PREFIX)
    sid, _raw = s.session(owner, uid, mfa=True)
    assert _row(owner, sid)[2] is not None


# ---------------------------------------------------------------------------
# rls-8: notify.enqueue
# ---------------------------------------------------------------------------

def _plan(*items: dict) -> str:
    return json.dumps(list(items))


IN_APP_SENT = {"channel": "IN_APP", "state": "SENT", "sent_at": "2020-01-01T00:00:00Z"}
SMTP_PENDING = {"channel": "SMTP", "state": "PENDING"}


def _enqueue_rolled_back(conn, recipient, actor, plan, *, read_back=False):
    """Run notify.enqueue inside a transaction that is rolled back (no
    notification row survives), optionally reading what it wrote as the
    owner. Returns (outcome, stored) where stored is None unless asked."""
    with conn.transaction(force_rollback=True):
        out = conn.execute(ENQUEUE, (recipient, actor, plan)).fetchone()
        stored = None
        if read_back and out[1] is not None:
            conn.execute("RESET ROLE")
            stored = conn.execute(
                """SELECT n.actor_id, array_agg(d.channel || ':' || d.state
                                                ORDER BY d.channel),
                          min(d.sent_at), now()
                     FROM notify.notification n
                     JOIN notify.delivery d ON d.notification_id = n.id
                    WHERE n.id = %s GROUP BY n.actor_id""", (out[1],)).fetchone()
        return out[0], stored


def test_an_unbound_caller_cannot_raise_a_notification(owner):
    victim = s.user(owner, prefix=PREFIX)
    app = s.app_conn(None)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="bound to no session"):
            _enqueue_rolled_back(app, victim, None, _plan(IN_APP_SENT))
    finally:
        app.close()


def test_a_bound_caller_cannot_sign_a_notice_as_somebody_else(owner):
    caller = s.user(owner, prefix=PREFIX)
    victim = s.user(owner, prefix=PREFIX)
    impersonated = s.user(owner, prefix=PREFIX)
    _sid, raw = s.session(owner, caller)
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege,
                           match="actor of a notice is the account that raises it"):
            _enqueue_rolled_back(app, victim, impersonated, _plan(IN_APP_SENT))
        # Its own id is fine. No actor at all was fine until 0181: a
        # request's notice now always names the account that raises it.
        outcome, stored = _enqueue_rolled_back(app, victim, caller, _plan(IN_APP_SENT),
                                               read_back=True)
        assert outcome == "WRITTEN" and stored[0] == caller
        with pytest.raises(psycopg.errors.InsufficientPrivilege,
                           match="actor of a notice is the account that raises it"):
            _enqueue_rolled_back(app, victim, None, _plan(IN_APP_SENT))
    finally:
        app.close()


@pytest.mark.parametrize("item", [
    {"channel": "SMTP", "state": "SENT", "sent_at": "2020-01-01T00:00:00Z"},
    {"channel": "WEBHOOK", "state": "SENT"},
    {"channel": "JIRA", "state": "SENT"},
    {"channel": "SMTP", "state": "FAILED"},
    {"channel": "SMTP", "state": "RETRY"},
    {"channel": "SMTP", "state": None},
    {"channel": "JIRA", "state": "PENDING", "blocked": {"state": "SENT"}},
    {"channel": "JIRA", "state": "PENDING", "blocked": {"state": "PENDING"}},
], ids=["smtp_sent", "webhook_sent", "jira_sent", "failed", "retry", "no_state",
        "blocked_sent", "blocked_pending"])
def test_a_forged_delivery_state_is_refused(owner, item):
    caller = s.user(owner, prefix=PREFIX)
    victim = s.user(owner, prefix=PREFIX)
    _sid, raw = s.session(owner, caller)
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="delivery is planned"):
            _enqueue_rolled_back(app, victim, caller, _plan(item))
    finally:
        app.close()


def test_the_plan_the_service_builds_is_accepted_and_a_sent_stamp_is_the_databases(owner):
    caller = s.user(owner, prefix=PREFIX)
    victim = s.user(owner, prefix=PREFIX)
    _sid, raw = s.session(owner, caller)
    app = s.app_conn(raw)
    try:
        plan = _plan(IN_APP_SENT, SMTP_PENDING,
                     {"channel": "WEBHOOK", "state": "SUPPRESSED", "cause": "BELOW_THRESHOLD",
                      "detail": "below the recipient's threshold"},
                     {"channel": "JIRA", "state": "PENDING",
                      "blocked": {"state": "SUPPRESSED", "cause": "CASE_NOT_ROUTED"}})
        outcome, stored = _enqueue_rolled_back(app, victim, caller, plan, read_back=True)
        assert outcome == "WRITTEN"
        assert stored[1] == ["IN_APP:SENT", "JIRA:PENDING", "SMTP:PENDING", "WEBHOOK:SUPPRESSED"]
        # sent_at on the SENT row is the database's clock, not 2020.
        assert abs((stored[3] - stored[2]).total_seconds()) < 5
    finally:
        app.close()


def test_a_caller_row_security_does_not_filter_keeps_the_function_it_had(owner):
    """The owner and the system role are trusted, as in 0112: a drain or a
    script may name an actor and any state."""
    victim = s.user(owner, prefix=PREFIX)
    someone = s.user(owner, prefix=PREFIX)
    plan = _plan({"channel": "SMTP", "state": "SENT", "sent_at": "2020-01-01T00:00:00Z"})
    outcome, stored = _enqueue_rolled_back(owner, victim, someone, plan, read_back=True)
    assert outcome == "WRITTEN"
    assert stored[0] == someone
    assert str(stored[2].year) == "2020", "an exempt caller's own sent_at is kept"


def test_the_notification_service_still_raises_a_notice_for_a_bound_request_role(owner):
    """The legitimate path end to end: the service builds the plan, the
    function accepts it, and the notice is the recipient's."""
    from noctornal_api.notifications import NotificationService
    caller = s.user(owner, "RED", prefix=PREFIX)
    recipient = s.user(owner, prefix=PREFIX)
    _sid, raw = s.session(owner, caller)
    app = s.app_conn(raw)
    try:
        with app.transaction(force_rollback=True):
            raised = NotificationService(app).enqueue(
                recipient_id=recipient, kind="APPROVAL_DECIDED",
                subject="Your request was countersigned: Change a role definition",
                summary="Your deployment-wide request was countersigned.",
                body="body text", classification="CLEAR", actor_id=caller)
            assert raised.outcome == "WRITTEN"
            assert raised.notification.actor_id == caller
    finally:
        app.close()


def test_execute_on_the_definers_is_not_public(owner):
    sig = ("notify.enqueue(uuid, uuid, text, smallint, text, text, text, core.tlp, "
           "text[], text, uuid, uuid, uuid, jsonb, jsonb)")
    acl = owner.execute("SELECT coalesce(proacl::text, '') FROM pg_proc "
                        "WHERE oid = %s::regprocedure", (sig,)).fetchone()[0]
    assert not re.search(r"(^|[{,])=X/", acl), "EXECUTE on notify.enqueue is still PUBLIC"
    for role in (s.APP_ROLE, s.WORKER_ROLE):
        assert owner.execute("SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')",
                             (role, sig)).fetchone()[0] is True


# ---------------------------------------------------------------------------
# Migrations round-trip
# ---------------------------------------------------------------------------

def test_the_five_migrations_declare_a_single_chain_and_a_real_downgrade():
    previous = "0142"
    for number in ("0143", "0144", "0145", "0146", "0147"):
        m = _migration(number)
        assert m.down_revision == previous, number
        assert m.revision == number
        assert callable(m.downgrade) and m.downgrade.__code__.co_code, number
        previous = number
