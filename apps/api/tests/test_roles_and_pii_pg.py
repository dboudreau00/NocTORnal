"""Migration 0062: the owner's role decisions of 2026-09-22, against a database.

"Keep the split": CASE_OWNER is the investigator who controls their case,
displayed as "Lead investigator" with the key unchanged, and
SECURITY_OFFICER stays the overseer who cannot read case content. From
that, docs/17 F16 and F14 are decided:

- `victim_pii.reveal` is granted to CASE_OWNER and `victim_pii.authorise`
  is REVOKED from it, so authorising is the Security Officer's alone and a
  reveal is two different people by construction;
- `break_glass.invoke` stays with CASE_OWNER and SYS_ADMIN, and
  `break_glass.review` with SECURITY_OFFICER only;
- `iam.separated_duty` names the pairs no single role may hold together,
  and a trigger on `iam.role_permission` refuses the grant that would.

What these tests carry: the grants as they stand at head, the migration's
own upgrade and downgrade run inside a transaction that is rolled back,
the upgrade revoking the authorisations a Lead investigator granted before
it (the verifier's transition hole of 2026-09-22), the guard judging an
in-place UPDATE on the grant it becomes, the guard refusing each
collapsing grant, the name reaching the console
through `GET /admin/roles`, and the whole two-person reveal over HTTP,
including the first-run operator who holds both roles and still cannot
authorise their own reveal.

Email prefix `rpii-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import date
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the role tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

PASSWORD = "correct-horse-battery-staple-9"
MIGRATION = (Path(__file__).resolve().parents[3] / "db" / "migrations"
             / "versions" / "0062_roles_and_pii.py")
COMPARTMENT = "STEALER-2026"
STEALER_RECORD = {
    "machine_id": "DESKTOP-RPII",
    "credentials": [{"url": "https://bank.example", "user": "victim@example",
                     "pass": "hunter2"}],
    "c2": "185.199.0.1:443",
    "builder": "RedLine 4.2",
    "captured": "2026-05-01T00:00:00Z",
}


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'rpii-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ksub = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    bsub = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {ksub})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {bsub})")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM ingest.pii_authorisation WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'rpii-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _holders(conn, permission: str) -> set[str]:
    return {r[0] for r in conn.execute(
        "SELECT role_key FROM iam.role_permission WHERE permission_key = %s",
        (permission,)).fetchall()}


def _user(conn, *roles: str) -> tuple:
    """An enrolled, RED-cleared account read into the stealer-log
    compartment, holding `roles` globally."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"rpii-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Rpii", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES "
                 "(%s, 'Stealer logs 2026 (test)') ON CONFLICT (key) DO NOTHING",
                 (COMPARTMENT,))
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED', "
                 "compartments = %s WHERE id = %s", ([COMPARTMENT], uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid, email


def _token(conn, uid) -> str:
    """A session minted as `scripts/bootstrap.py session` mints one, with
    MFA satisfied now, so the step-up permissions under test are fresh."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner) -> str:
    """Created through the service, which assigns the owner CASE_OWNER on
    the case in the same transaction, exactly as the route does."""
    from noctornal_api.cases import CaseService
    return str(CaseService(conn).create(
        code=f"OP-RPII-{uuid4().hex[:6]}", title="Two-person reveal",
        legal_basis="production order 2026-0001",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner))


def _credential(conn, owner, case_id) -> str:
    """One masked victim credential in `case_id`, ingested the way
    test_ingest_pg ingests one."""
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    svc = IngestService(conn, InMemoryRawStorage())
    issued = svc.issue_key(name="partner feed", owner_user_id=owner,
                           declared_category="STEALER_LOG",
                           forced_compartment=COMPARTMENT)
    key = svc.authenticate(issued.secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]
    return str(svc.store_credential(record_id, kind="PASSWORD", value="hunter2"))


def _authorise(client, token, case_id, granted_to):
    return client.post(
        "/api/v1/ingest/pii-authorisations", headers=_auth(token),
        json={"case_id": case_id, "granted_to": str(granted_to),
              "scope_note": "credentials for the victim organisation named "
                            "in this production order only",
              "legal_basis": "production order 2026-0001"})


# ---------------------------------------------------------------------------
# The grants at head
# ---------------------------------------------------------------------------

def test_case_owner_is_displayed_as_lead_investigator(conn):
    """The label moves and the key does not: every permission check, case
    assignment and test reads the key."""
    row = conn.execute(
        "SELECT display_name, description FROM iam.role WHERE key = 'CASE_OWNER'"
    ).fetchone()
    assert row is not None, "the CASE_OWNER key moved; no check would find it"
    assert row[0] == "Lead investigator"
    assert "Security officer" in row[1], (
        "the description no longer says who authorises the reveal")
    # No second role wears the name.
    assert conn.execute(
        "SELECT count(*) FROM iam.role WHERE display_name = 'Lead investigator'"
    ).fetchone()[0] == 1


def test_victim_pii_is_two_people_by_construction(conn):
    """docs/17 F16. Until 0062 nothing held `reveal`, so the route refused
    everyone, and CASE_OWNER held `authorise` alongside SECURITY_OFFICER."""
    assert _holders(conn, "victim_pii.reveal") == {"CASE_OWNER"}
    assert _holders(conn, "victim_pii.authorise") == {"SECURITY_OFFICER"}


def test_break_glass_holders_are_the_decided_ones(conn):
    """docs/17 F14, decided 2026-09-22: unchanged from 0039, and now a
    decision rather than a guess."""
    assert _holders(conn, "break_glass.invoke") == {"CASE_OWNER", "SYS_ADMIN"}
    assert _holders(conn, "break_glass.review") == {"SECURITY_OFFICER"}


def test_no_role_holds_both_halves_of_any_separated_pair(conn):
    pairs = {tuple(sorted(r)) for r in conn.execute(
        "SELECT permission_a, permission_b FROM iam.separated_duty").fetchall()}
    assert {("victim_pii.authorise", "victim_pii.reveal"),
            ("break_glass.invoke", "break_glass.review"),
            ("sample.preserved.authorise", "sample.preserved.retrieve")} <= pairs
    assert conn.execute(
        "SELECT * FROM iam.separated_duty_violations()").fetchall() == []


@pytest.mark.parametrize("role, permission", [
    ("SECURITY_OFFICER", "victim_pii.reveal"),
    ("CASE_OWNER", "victim_pii.authorise"),
    ("SECURITY_OFFICER", "break_glass.invoke"),
    ("CASE_OWNER", "break_glass.review"),
    ("SYS_ADMIN", "break_glass.review"),
])
def test_a_grant_that_collapses_two_people_into_one_role_is_refused(
        conn, role, permission):
    """The trigger, per pair and in both directions. A role definition is
    what no request-time check can see: every holder of it would be both
    people at once."""
    try:
        with pytest.raises(psycopg.errors.RaiseException,
                           match="two-person control"):
            conn.execute("INSERT INTO iam.role_permission (role_key, "
                         "permission_key) VALUES (%s, %s)", (role, permission))
    finally:
        # Only reached with a row in place if the guard is missing; none of
        # these pairs is ever a seeded grant, so removing it is safe.
        conn.execute("DELETE FROM iam.role_permission WHERE role_key = %s "
                     "AND permission_key = %s", (role, permission))


def test_a_pair_cannot_be_declared_over_a_role_that_already_breaks_it(conn):
    """Two permissions of this test's own, so the only role holding both is
    the one it made (seeded roles hold plenty of pairs nobody separates)."""
    tag = uuid4().hex[:6]
    role, a, b = f"RPII_{tag.upper()}", f"rpii.{tag}.a", f"rpii.{tag}.b"
    conn.execute("INSERT INTO iam.role (key, display_name, description, "
                 "is_system) VALUES (%s, 'Test role', 'rpii', false)", (role,))
    conn.execute("INSERT INTO iam.permission (key, description) VALUES "
                 "(%s, 'rpii test'), (%s, 'rpii test')", (a, b))
    try:
        conn.execute("INSERT INTO iam.role_permission VALUES (%s, %s), (%s, %s)",
                     (role, a, role, b))
        with pytest.raises(psycopg.errors.RaiseException, match=role):
            conn.execute("INSERT INTO iam.separated_duty VALUES "
                         "(%s, %s, 'test pair')", (a, b))
    finally:
        conn.execute("DELETE FROM iam.separated_duty WHERE why = 'test pair'")
        conn.execute("DELETE FROM iam.role_permission WHERE role_key = %s", (role,))
        conn.execute("DELETE FROM iam.permission WHERE key IN (%s, %s)", (a, b))
        conn.execute("DELETE FROM iam.role WHERE key = %s", (role,))


# ---------------------------------------------------------------------------
# The migration's own two directions, rolled back
# ---------------------------------------------------------------------------

class _RollBack(Exception):
    pass


def _migration(conn):
    spec = importlib.util.spec_from_file_location("m0062", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def test_the_migration_downgrades_and_upgrades_what_it_says(conn):
    """Both directions against the real schema, inside one transaction that
    is rolled back, so the database the rest of the suite uses never sees
    the intermediate state. `alembic downgrade 0061` / `upgrade head` was
    also run by hand on 2026-09-22; this keeps it true."""
    m = _migration(conn)
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        assert conn.execute("SELECT display_name FROM iam.role WHERE key = "
                            "'CASE_OWNER'").fetchone()[0] == "Case owner"
        assert _holders(conn, "victim_pii.reveal") == set()
        assert _holders(conn, "victim_pii.authorise") == {
            "CASE_OWNER", "SECURITY_OFFICER"}
        assert conn.execute(
            "SELECT to_regclass('iam.separated_duty')").fetchone()[0] is None
        # A second downgrade is a no-op, as it must be on a database that
        # was stamped through the 0062 stub.
        m.downgrade()

        m.upgrade()
        assert conn.execute("SELECT display_name FROM iam.role WHERE key = "
                            "'CASE_OWNER'").fetchone()[0] == "Lead investigator"
        assert _holders(conn, "victim_pii.reveal") == {"CASE_OWNER"}
        assert _holders(conn, "victim_pii.authorise") == {"SECURITY_OFFICER"}
        raise _RollBack


def _pii_authorisation(conn, case_id, by, to, *, days_ago=0,
                       revoked=False):
    """A row as `grant_pii_authorisation` writes one, placed directly so
    it can predate the grant change. `days_ago=31` gives one that has
    already expired inside its 30-day window."""
    return conn.execute(
        """INSERT INTO ingest.pii_authorisation
               (case_id, granted_to, granted_by, scope_note, legal_basis,
                granted_at, expires_at, revoked_at)
           VALUES (%s, %s, %s,
                   'credentials for the victim organisation named in the order',
                   'production order 2026-0001',
                   now() - make_interval(days => %s),
                   now() - make_interval(days => %s) + interval '30 days',
                   CASE WHEN %s THEN now() - interval '1 hour' END)
           RETURNING id, revoked_at""",
        (case_id, to, by, days_ago, days_ago, revoked)).fetchone()


def test_the_upgrade_revokes_what_a_lead_investigator_authorised(conn):
    """The transition hole the verifier reproduced on 2026-09-22. Before
    0062 a CASE_OWNER held `authorise`, so a lead could authorise a co-lead
    for up to 30 days; the row opened nothing while nobody held `reveal`.
    After 0062 the co-lead holds `reveal`, and `_live_authorisation` never
    asks who granted the row, so it would have opened a reveal no Security
    Officer authorised. The upgrade revokes exactly the rows whose grantor
    could not grant them today, records why, and leaves the officer's."""
    from noctornal_api.cases import CaseService
    from noctornal_api.ingest import IngestService
    lead, _ = _user(conn, "CASE_OWNER")
    co_lead, _ = _user(conn, "CASE_OWNER")
    officer, _ = _user(conn, "SECURITY_OFFICER")
    case_id = _case(conn, lead)
    cases = CaseService(conn)
    cases.assign_user_checked(case_id, co_lead, "CASE_OWNER", granted_by=lead)
    cases.assign_user_checked(case_id, officer, "SECURITY_OFFICER",
                              granted_by=lead)
    m = _migration(conn)
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        stale, _ = _pii_authorisation(conn, case_id, lead, co_lead)
        kept, _ = _pii_authorisation(conn, case_id, officer, lead)
        lapsed, _ = _pii_authorisation(conn, case_id, lead, officer, days_ago=31)
        earlier, earlier_at = _pii_authorisation(conn, case_id, lead, co_lead,
                                                 revoked=True)
        ingest = IngestService(conn)
        assert ingest._live_authorisation(co_lead, case_id) == stale, (
            "the reproduction needs the lead-granted row live before 0062")

        m.upgrade()

        revoked = dict(conn.execute(
            "SELECT id, revoked_at FROM ingest.pii_authorisation "
            "WHERE case_id = %s", (case_id,)).fetchall())
        assert revoked[stale] is not None, "the lead-granted row is still live"
        assert revoked[kept] is None, "the officer's authorisation was revoked"
        assert revoked[lapsed] is None, "an expired row was touched"
        assert revoked[earlier] == earlier_at, "an earlier revocation moved"
        assert ingest._live_authorisation(co_lead, case_id) is None
        assert ingest._live_authorisation(lead, case_id) == kept

        events = conn.execute(
            """SELECT object_id, actor_id, actor_kind, case_id, detail
                 FROM audit.event
                WHERE action = 'PII_AUTHORISATION_REVOKED'
                  AND object_id = ANY(%s)""",
            ([stale, kept, lapsed, earlier],)).fetchall()
        assert len(events) == 1, events
        object_id, actor_id, actor_kind, event_case, detail = events[0]
        assert (object_id, actor_id, actor_kind) == (stale, None, "SYSTEM")
        assert str(event_case) == case_id
        assert detail["granted_by"] == str(lead)
        assert detail["granted_to"] == str(co_lead)
        assert detail["by"] == "migration 0062"
        assert "Security Officer" in detail["reason"]
        raise _RollBack


def test_moving_a_grant_in_place_is_judged_on_the_grant_it_becomes(conn):
    """The verifier's false positive of 2026-09-22: a BEFORE UPDATE trigger
    still sees the row it is replacing, so turning CASE_OWNER's `reveal`
    into `authorise` in place was refused over the very `reveal` it was
    replacing. The guard now excludes the old row, and moving a half onto a
    role that holds the other half is still refused."""
    with pytest.raises(_RollBack), conn.transaction():
        conn.execute("UPDATE iam.role_permission "
                     "SET permission_key = 'victim_pii.authorise' "
                     "WHERE role_key = 'CASE_OWNER' "
                     "AND permission_key = 'victim_pii.reveal'")
        assert _holders(conn, "victim_pii.reveal") == set()
        assert _holders(conn, "victim_pii.authorise") == {
            "CASE_OWNER", "SECURITY_OFFICER"}
        raise _RollBack
    with pytest.raises(psycopg.errors.RaiseException,
                       match="two-person control"), conn.transaction():
        conn.execute("UPDATE iam.role_permission SET role_key = 'CASE_OWNER' "
                     "WHERE role_key = 'SECURITY_OFFICER' "
                     "AND permission_key = 'victim_pii.authorise'")
    assert _holders(conn, "victim_pii.reveal") == {"CASE_OWNER"}
    assert _holders(conn, "victim_pii.authorise") == {"SECURITY_OFFICER"}


def test_the_upgrade_refuses_a_role_that_already_holds_both_halves(conn):
    """Installing the guard over a violation would report the control as
    present while it is not. The upgrade names the role and stops."""
    m = _migration(conn)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="SECURITY_OFFICER holds victim_pii.authorise and "
                             "victim_pii.reveal"), conn.transaction():
        m.downgrade()
        conn.execute("INSERT INTO iam.role_permission VALUES "
                     "('SECURITY_OFFICER', 'victim_pii.reveal')")
        m.upgrade()
    assert _holders(conn, "victim_pii.reveal") == {"CASE_OWNER"}


# ---------------------------------------------------------------------------
# The name reaches the console
# ---------------------------------------------------------------------------

def test_the_admin_pane_reads_role_names_from_the_server(conn, client):
    uid, _ = _user(conn, "SYS_ADMIN")
    r = client.get("/api/v1/admin/roles", headers=_auth(_token(conn, uid)))
    assert r.status_code == 200, r.text
    roles = {x["key"]: x for x in r.json()["roles"]}
    assert roles["CASE_OWNER"]["display_name"] == "Lead investigator"
    assert roles["CASE_OWNER"]["grantable"] is True
    assert roles["SERVICE"]["grantable"] is False
    from noctornal_api.iam_admin import GRANTABLE_ROLES
    assert {k for k, x in roles.items() if x["grantable"]} == set(GRANTABLE_ROLES)


def test_the_role_names_are_an_administrators_read(conn, client):
    assert client.get("/api/v1/admin/roles").status_code == 401
    uid, _ = _user(conn, "ANALYST")
    r = client.get("/api/v1/admin/roles", headers=_auth(_token(conn, uid)))
    assert r.status_code == 403
    assert "user.manage" in r.json()["detail"]


# ---------------------------------------------------------------------------
# The reveal, end to end over HTTP
# ---------------------------------------------------------------------------

def test_the_reveal_takes_a_lead_investigator_and_a_different_officer(
        conn, client):
    """The whole of docs/17 F16 as the product performs it. The officer is
    assigned to the case as SECURITY_OFFICER, which confers `authorise`
    and no case content; the Lead investigator's own assignment confers
    `reveal` and not `authorise`. Neither can do the other's half."""
    from noctornal_api.cases import CaseService
    lead, _ = _user(conn, "CASE_OWNER")
    officer, _ = _user(conn, "SECURITY_OFFICER")
    case_id = _case(conn, lead)
    CaseService(conn).assign_user_checked(case_id, officer, "SECURITY_OFFICER",
                                          granted_by=lead)
    cred = _credential(conn, lead, case_id)
    lead_token, officer_token = _token(conn, lead), _token(conn, officer)
    reveal = {"case_id": case_id, "reason": "victim organisation attribution"}
    path = f"/api/v1/ingest/credentials/{cred}/reveal"

    # The Lead investigator cannot authorise anybody, themselves included.
    for target in (lead, officer):
        r = _authorise(client, lead_token, case_id, target)
        assert r.status_code == 403, r.text
        assert "victim_pii.authorise" in r.json()["detail"]

    # Before any authorisation the reveal is refused by the CONTROL (451),
    # not by a missing permission: the lead now holds `reveal`.
    r = client.post(path, headers=_auth(lead_token), json=reveal)
    assert r.status_code == 451, r.text

    # The officer authorises the lead, and cannot reveal themselves.
    r = _authorise(client, officer_token, case_id, lead)
    assert r.status_code == 201, r.text
    r = client.post(path, headers=_auth(officer_token), json=reveal)
    assert r.status_code == 403, r.text

    r = client.post(path, headers=_auth(lead_token), json=reveal)
    assert r.status_code == 200, r.text
    assert r.json()["value"] == "hunter2"
    row = conn.execute(
        "SELECT granted_to, granted_by FROM ingest.pii_authorisation "
        "WHERE case_id = %s", (case_id,)).fetchone()
    assert (str(row[0]), str(row[1])) == (str(lead), str(officer))


def test_an_operator_holding_both_roles_cannot_authorise_their_own_reveal(
        conn, client):
    """The first-run operator holds SYS_ADMIN, SECURITY_OFFICER, CASE_OWNER
    and ANALYST (`iam_admin`), so both halves are theirs globally. On their
    own case their ONE assignment is CASE_OWNER, which holds `reveal` and
    not `authorise`, so the case gate refuses before the self-check is
    even reached. Before 0062 it reached the self-check only because
    CASE_OWNER held `authorise` too."""
    both, _ = _user(conn, "SECURITY_OFFICER", "CASE_OWNER")
    case_id = _case(conn, both)
    r = _authorise(client, _token(conn, both), case_id, both)
    assert r.status_code == 403, r.text
    assert "victim_pii.authorise" in r.json()["detail"]
