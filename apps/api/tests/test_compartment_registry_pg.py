"""The compartment registry (migration 0057) and the write sites it gates.

`iam.app_user.compartments` and `core.case.compartments` were free-text
arrays validated by nothing, and the user-side array had no product write
path at all: a compartment was granted with `psql`, and a typo in it was
silent no-access -- the analyst simply stopped seeing the case, and no
listing, gate or log said why (docs/16's lesson, cited in `iam_admin.py`'s
role allowlist since 2026-07-30 and never applied to compartments).

`iam.compartment` is now the closed vocabulary. The tests that carry this
file read BOTH sides of that contract wherever it crosses a file:

- the SERVICE refusal (`CaseError` naming the key) and the ROUTER's 400
  for the same request, so the wire cannot drift from the reason;
- the MIGRATION's own backfill SQL, imported from the version file and
  run against a seeded row, so "the backfill registered the pre-existing
  values" is proved rather than assumed on a database that happens to
  already contain them;
- the one place a compartment could be smuggled past the gate -- a case
  edit -- checked on the router body AND the service signature, so adding
  the field to either half without the other fails here.

Env-gated on DATABASE_URL. Email prefix `cmp-`; registry keys `ALPHA-T6-`.
"""
from __future__ import annotations

import importlib.util
import os
import time
from datetime import date
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; registry tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-7"
EMAIL_LIKE = "cmp-%@noctornal.test"
KEY_LIKE = "ALPHA-T6-%"
ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "db" / "migrations" / "versions" / "0057_compartment_registry.py"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
        # Guarded so the teardown itself does not fail on the code before
        # 0057, where the table is what the tests prove is missing.
        if c.execute("SELECT to_regclass('iam.compartment')").fetchone()[0]:
            c.execute(f"DELETE FROM iam.compartment WHERE key LIKE '{KEY_LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _key() -> str:
    return f"ALPHA-T6-{uuid4().hex[:6].upper()}"


def _user(conn, *global_roles, clearance="AMBER", compartments=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"cmp-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Cmp", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    # Direct SQL, as every fixture in this suite does: this is the
    # out-of-band path the registry does not gate, and the tests below
    # are explicit about which side of that line they stand on.
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s WHERE id = %s",
        (clearance, list(compartments), uid))
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case_body(compartments: list[str]) -> dict:
    return {"code": f"OP-CMP-{uuid4().hex[:6]}", "title": "Compartmented",
            "legal_basis": "production order 2026-0007",
            "retention_until": str(date(2028, 1, 1)),
            "review_due": str(date(2027, 1, 1)),
            "compartments": compartments}


def _create(conn, owner, compartments):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-CMP-{uuid4().hex[:6]}", title="Compartmented",
        legal_basis="production order 2026-0007",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, compartments=compartments)


def _admin_svc(conn):
    from noctornal_api.iam_admin import IamAdminService
    return IamAdminService(conn)


# --- the case write site --------------------------------------------------

def test_a_case_cannot_enter_a_compartment_until_it_is_registered(conn, client):
    """Before registration: refused, and the refusal NAMES the key, on the
    service and on the wire. After POST /compartments: the same request
    succeeds. The owner already holds the key (out of band), so the only
    thing standing between the two outcomes is the registry."""
    from noctornal_api.cases import CaseError
    key = _key()
    owner_id, owner_email, owner_secret = _user(conn, "CASE_OWNER",
                                                compartments=(key,))
    admin_id, admin_email, admin_secret = _user(conn, "SYS_ADMIN")
    owner = _login(client, owner_email, owner_secret)

    r = client.post("/api/v1/cases", headers=_auth(owner), json=_case_body([key]))
    assert r.status_code == 400, r.text
    assert key in r.text and "regist" in r.text
    assert r.headers["content-type"].startswith("application/problem+json")
    with pytest.raises(CaseError, match=key):
        _create(conn, owner_id, [key])
    assert conn.execute(
        'SELECT count(*) FROM core."case" WHERE owner_user_id = %s',
        (owner_id,)).fetchone()[0] == 0

    admin = _login(client, admin_email, admin_secret)
    made = client.post("/api/v1/compartments", headers=_auth(admin),
                       json={"key": key, "label": "Alpha (test)"})
    assert made.status_code == 201, made.text
    assert made.json()["key"] == key and made.json()["created_by"] == str(admin_id)

    r = client.post("/api/v1/cases", headers=_auth(owner), json=_case_body([key]))
    assert r.status_code == 201, r.text
    assert _create(conn, owner_id, [key])

    # The owner is read into this key, so the listing shows it to them.
    # WHO may read what is pinned by
    # `test_the_listing_shows_only_the_callers_own_read_ins` below.
    listed = client.get("/api/v1/compartments", headers=_auth(owner))
    assert listed.status_code == 200, listed.text
    mine = [c for c in listed.json()["compartments"] if c["key"] == key]
    assert mine and mine[0]["label"] == "Alpha (test)"
    assert client.get("/api/v1/compartments").status_code == 401
    # Registering is `user.manage`: an owner is refused.
    assert client.post("/api/v1/compartments", headers=_auth(owner),
                       json={"key": _key(), "label": "x"}).status_code == 403
    assert conn.execute(
        """SELECT 1 FROM audit.event
            WHERE action = 'COMPARTMENT_REGISTERED' AND detail->>'key' = %s""",
        (key,)).fetchone() is not None


def test_registering_the_same_key_twice_is_a_refusal_not_a_relabel(conn):
    """`ON CONFLICT DO UPDATE` here would let a second admin silently
    rename what every case in the compartment is filed under."""
    from noctornal_api.iam_admin import AdminError
    key = _key()
    admin_id, _, _ = _user(conn, "SYS_ADMIN")
    svc = _admin_svc(conn)
    svc.register_compartment(key=key, label="First", actor_id=admin_id)
    with pytest.raises(AdminError, match="already"):
        svc.register_compartment(key=key, label="Second", actor_id=admin_id)
    assert conn.execute(
        "SELECT label FROM iam.compartment WHERE key = %s", (key,)
    ).fetchone()[0] == "First"


def test_the_listing_shows_only_the_callers_own_read_ins(conn, client):
    """The access decision on `GET /compartments`, which had no test at all
    until 2026-09-02 -- the one thing in this surface nobody had pinned.

    Until then the endpoint was gated on `current_user` alone and returned
    the WHOLE registry, with each key's administrator-written label, to
    every authenticated account. In this system the key IS the
    need-to-know lock: 0057 calls compartments "need-to-know locks" and
    `cases.py` refuses an unregistered key because "a key is something
    typed into a warrant schedule". Handing an analyst with zero read-ins
    the full codeword vocabulary told them which operations exist, which
    is the fact the compartment was created to withhold.

    Three parties, one URL, and the response says which answer it is --
    because a listing that silently narrows is a correct answer to a
    different question, and the client cannot tell.
    """
    held, unheld = _key(), _key()
    admin_id, admin_email, admin_secret = _user(conn, "SYS_ADMIN")
    svc = _admin_svc(conn)
    svc.register_compartment(key=held, label="Held", actor_id=admin_id)
    svc.register_compartment(key=unheld, label="Not held", actor_id=admin_id)

    _, analyst_email, analyst_secret = _user(conn, compartments=(held,))
    analyst = _login(client, analyst_email, analyst_secret)
    body = client.get("/api/v1/compartments", headers=_auth(analyst))
    assert body.status_code == 200, body.text
    # The disclosure itself first, so a regression here fails saying what
    # actually leaked rather than which field went missing.
    assert unheld not in body.text, (
        "an analyst must not be able to enumerate compartments they are "
        "not read into: the key IS the need-to-know lock, so the list of "
        "keys is the list of operations that exist")
    assert [c["key"] for c in body.json()["compartments"]] == [held]
    assert set(body.json()["compartments"][0]) == {"key", "label"}, (
        "who registered a compartment and when is registry administration, "
        "not something a read-in entitles you to")
    assert body.json()["scope"] == "held"
    assert body.json()["count"] == 1

    # The account that maintains the registry sees the registry.
    admin = _login(client, admin_email, admin_secret)
    whole = client.get("/api/v1/compartments", headers=_auth(admin))
    assert whole.status_code == 200, whole.text
    assert whole.json()["scope"] == "all"
    keys = {c["key"] for c in whole.json()["compartments"]}
    assert {held, unheld} <= keys
    entry = next(c for c in whole.json()["compartments"] if c["key"] == held)
    assert entry["created_by"] == str(admin_id) and entry["created_at"]

    # `holds_global_permission` widens a READ and must never be mistaken
    # for authorisation to write: the analyst still cannot register.
    assert client.post("/api/v1/compartments", headers=_auth(analyst),
                       json={"key": _key(), "label": "x"}).status_code == 403
    assert client.get("/api/v1/compartments").status_code == 401


# --- the user write site --------------------------------------------------

def test_set_compartments_refuses_a_typo_and_a_stranding_removal(conn, client):
    """The two refusals that make the user-side write path safe to expose:
    an unknown key is named and refused (the typo that used to be silent
    no-access), and a compartment an OWNED case requires cannot be taken
    away -- the mirror of the clearance-lowering refusal, for the same
    reason: an owner who cannot read their own case has no route back."""
    from noctornal_api.iam_admin import AdminError
    key = _key()
    admin_id, admin_email, admin_secret = _user(conn, "SYS_ADMIN")
    owner_id, _, _ = _user(conn, "CASE_OWNER")
    svc = _admin_svc(conn)
    svc.register_compartment(key=key, label="Alpha", actor_id=admin_id)

    svc.set_compartments(owner_id, [key], actor_id=admin_id)
    assert conn.execute(
        "SELECT compartments FROM iam.app_user WHERE id = %s", (owner_id,)
    ).fetchone()[0] == [key]
    audit = conn.execute(
        """SELECT detail FROM audit.event
            WHERE object_id = %s AND action = 'USER_COMPARTMENTS_CHANGED'
            ORDER BY seq DESC LIMIT 1""", (owner_id,)).fetchone()[0]
    assert audit["from"] == [] and audit["to"] == [key]

    typo = key + "X"
    with pytest.raises(AdminError, match=typo):
        svc.set_compartments(owner_id, [key, typo], actor_id=admin_id)
    assert conn.execute(
        "SELECT compartments FROM iam.app_user WHERE id = %s", (owner_id,)
    ).fetchone()[0] == [key], "a refused write must change nothing"

    case_id = _create(conn, owner_id, [key])
    with pytest.raises(AdminError, match="strand") as refused:
        svc.set_compartments(owner_id, [], actor_id=admin_id)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]
    assert code in str(refused.value) and key in str(refused.value)
    # Re-stating the same set is not an error and writes no audit row.
    before = conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE object_id = %s AND action = 'USER_COMPARTMENTS_CHANGED'""",
        (owner_id,)).fetchone()[0]
    svc.set_compartments(owner_id, [key], actor_id=admin_id)
    assert conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE object_id = %s AND action = 'USER_COMPARTMENTS_CHANGED'""",
        (owner_id,)).fetchone()[0] == before
    with pytest.raises(AdminError, match="no such user"):
        svc.set_compartments(uuid4(), [key], actor_id=admin_id)

    # Over the wire: same refusals, same words, under user.manage.
    admin = _login(client, admin_email, admin_secret)
    r = client.put(f"/api/v1/compartments/users/{owner_id}", headers=_auth(admin),
                   json={"compartments": [key, typo]})
    assert r.status_code == 409, r.text
    assert typo in r.text
    r = client.put(f"/api/v1/compartments/users/{owner_id}", headers=_auth(admin),
                   json={"compartments": []})
    assert r.status_code == 409 and "strand" in r.text
    r = client.put(f"/api/v1/compartments/users/{uuid4()}", headers=_auth(admin),
                   json={"compartments": [key]})
    assert r.status_code == 404, r.text
    _, plain_email, plain_secret = _user(conn)
    plain = _login(client, plain_email, plain_secret)
    assert client.put(f"/api/v1/compartments/users/{owner_id}", headers=_auth(plain),
                      json={"compartments": []}).status_code == 403


def test_narrowing_a_read_in_reports_the_assignments_it_strands(conn):
    """The gap between what `set_compartments`' refusal covers and what its
    reasoning claimed, closed on 2026-09-02 by reporting rather than by
    refusing more.

    The refusal covers OWNER and DEPUTY, because those have no route back:
    an owner locked out of their own case cannot transfer it. An ASSIGNEE
    does have one, so refusing there would mean an administrator cannot
    narrow anyone's read-ins until every case they are on is unpicked --
    and a control nobody can use is not a control. But losing a case you
    are assigned to is still silent no-access, so the act is recorded
    instead of prevented.

    Both halves, because the audit row is a CLAIM about access: the
    detail names the case, and `list_for_user` -- the listing that must
    return exactly what the five-part gate allows -- agrees that the
    analyst can no longer see it.
    """
    from noctornal_api.cases import CaseService
    from noctornal_api.iam_admin import AdminError
    key = _key()
    admin_id, _, _ = _user(conn, "SYS_ADMIN")
    owner_id, _, _ = _user(conn, "CASE_OWNER", clearance="RED",
                           compartments=(key,))
    analyst_id, _, _ = _user(conn, clearance="RED", compartments=(key,))
    svc = _admin_svc(conn)
    svc.register_compartment(key=key, label="Alpha", actor_id=admin_id)
    case_id = _create(conn, owner_id, [key])
    cases = CaseService(conn)
    cases.assign_user(case_id, analyst_id, "ANALYST", granted_by=owner_id)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]
    assert code in [c.code for c in cases.list_for_user(analyst_id)]

    svc.set_compartments(analyst_id, [], actor_id=admin_id)

    detail = conn.execute(
        """SELECT detail FROM audit.event
            WHERE object_id = %s AND action = 'USER_COMPARTMENTS_CHANGED'
            ORDER BY seq DESC LIMIT 1""", (analyst_id,)).fetchone()[0]
    assert detail["stranded_assignments"] == [code], (
        "an assignee who quietly loses a case is the silent no-access this "
        "registry exists to end; the act is allowed, so it must be visible")
    assert code not in [c.code for c in cases.list_for_user(analyst_id)], (
        "the audit row claims the analyst lost the case -- the gate has to "
        "agree, or the record is about something that did not happen")

    # The owner is still REFUSED outright: that is the position with no
    # route back, and reporting is not enough for it.
    with pytest.raises(AdminError, match="strand"):
        svc.set_compartments(owner_id, [], actor_id=admin_id)


def test_the_key_format_is_enforced_on_every_way_in(conn, client):
    """`^[A-Z0-9_-]{2,32}$`: a key is something typed into a warrant
    schedule and compared byte-for-byte by the access gate, so case and
    whitespace variants are not "the same compartment", they are a second
    one that nobody holds."""
    from noctornal_api.iam_admin import AdminError
    admin_id, admin_email, admin_secret = _user(conn, "SYS_ADMIN")
    svc = _admin_svc(conn)
    for bad in ("alpha-t6-x", "ALPHA T6", "A", "X" * 33, ""):
        with pytest.raises(AdminError, match="A-Z0-9"):
            svc.register_compartment(key=bad, label="x", actor_id=admin_id)
    admin = _login(client, admin_email, admin_secret)
    r = client.post("/api/v1/compartments", headers=_auth(admin),
                    json={"key": "alpha-t6-lower", "label": "x"})
    assert r.status_code == 409, r.text
    assert "A-Z0-9" in r.text
    # The schema holds the same line for a write that bypasses the service.
    import psycopg
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "INSERT INTO iam.compartment (key, label) VALUES ('alpha-t6-sql', 'x')")


# --- the migration --------------------------------------------------------

def _m0057():
    """The version file itself, loaded as a module.

    Read from the file rather than reimplemented here: a test that
    restates the migration's SQL proves the test agrees with the test.
    """
    spec = importlib.util.spec_from_file_location("m0057", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _backfill_sql() -> str:
    return _m0057().BACKFILL_SQL


def test_the_backfill_registers_every_value_already_in_either_array(conn):
    """Two halves. The migrated database: every distinct value in either
    array is registered, which is what an upgrade must leave behind. And
    the backfill statement ITSELF, run from the version file against a row
    seeded inside a rolled-back transaction -- because on CI the arrays
    are empty and the first half is vacuously true there."""
    unregistered = conn.execute(
        """SELECT array_agg(DISTINCT c ORDER BY c)
             FROM (SELECT unnest(compartments) AS c FROM iam.app_user
                   UNION SELECT unnest(compartments) FROM core."case") s
            WHERE NOT EXISTS (SELECT 1 FROM iam.compartment k WHERE k.key = s.c)"""
    ).fetchone()[0]
    assert unregistered is None, unregistered

    import psycopg

    from noctornal_api.db import dsn
    key = _key()
    tx = psycopg.connect(dsn())
    try:
        tx.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash,
                                         compartments)
               VALUES (%s, 'Backfill', 'x', %s)""",
            (f"cmp-{uuid4().hex[:8]}@noctornal.test", [key]))
        assert tx.execute("SELECT 1 FROM iam.compartment WHERE key = %s",
                          (key,)).fetchone() is None
        tx.execute(_backfill_sql())
        row = tx.execute(
            "SELECT label, created_by FROM iam.compartment WHERE key = %s",
            (key,)).fetchone()
        assert row == (key, None), "backfilled entries are labelled with the key"
        # Idempotent: a second run on the same data changes nothing.
        tx.execute(_backfill_sql())
        assert tx.execute("SELECT count(*) FROM iam.compartment WHERE key = %s",
                          (key,)).fetchone()[0] == 1
    finally:
        tx.rollback()
        tx.close()


def test_a_legacy_value_the_format_cannot_hold_stops_the_upgrade_with_the_fix(conn):
    """0057 hard-fails on a value it cannot register, so the refusal has to
    be an instruction rather than a wall -- and the instruction has to run.

    Three halves of one contract, and the third is the one that was
    missing until 2026-09-02. `test_notifications_pg.py` wrote the
    compartment `'A'` into `iam.app_user.compartments`; a run interrupted
    before its teardown leaves that behind, and the next `alembic upgrade`
    on that database stops at 0057 forever. The migration's docstring now
    says the refusal is a documented pre-upgrade cleanup step, so this
    pins that the cleanup exists, names the value, and WORKS:

    - the schema genuinely cannot hold the value (so skipping it, rather
      than refusing, would strand every case filed under it);
    - `UNREGISTRABLE_SQL` finds it in either array;
    - the SQL `refusal_message` prints is executable, touches BOTH arrays,
      and leaves `UNREGISTRABLE_SQL` empty -- i.e. the operator who does
      what the error says can then complete the upgrade.
    """
    import psycopg

    from noctornal_api.db import dsn
    m = _m0057()
    legacy = "A"           # one character: `^[A-Z0-9_-]{2,32}$` can never take it
    good = _key()

    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                     (legacy,))

    email = f"cmp-{uuid4().hex[:8]}@noctornal.test"
    tx = psycopg.connect(dsn())
    try:
        uid = tx.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash,
                                         tlp_clearance, compartments)
               VALUES (%s, 'Legacy', 'x', 'RED', %s) RETURNING id""",
            (email, [legacy])).fetchone()[0]
        # Raw SQL, not `CaseService.create`: the service now REFUSES this
        # key, which is the point -- this is the pre-0057 row an upgrade
        # actually finds, not one the product could still make today.
        tx.execute(
            """INSERT INTO core."case" (code, title, status, legal_basis,
                                        retention_until, review_due,
                                        classification, compartments,
                                        owner_user_id)
               VALUES (%s, 'Legacy', 'DRAFT', 'production order', '2028-01-01',
                       '2027-01-01', 'AMBER', %s, %s)""",
            (f"OP-CMP-{uuid4().hex[:6]}", [legacy], uid))
        assert [r[0] for r in tx.execute(m.UNREGISTRABLE_SQL).fetchall()] == [legacy]

        message = m.refusal_message([legacy])
        assert f"'{legacy}'" in message, "the operator must be told WHICH value"
        assert "iam.app_user" in message and 'core."case"' in message, (
            "renaming one array and not the other is the typo 0057 exists "
            "to stop; the fix has to name both")
        assert m.REPLACEMENT in message

        # The printed cleanup, actually run -- the rename branch, not the
        # `array_remove` one, which is offered second because dropping a
        # lock declassifies every case that carried it.
        assert m.rename_sql(legacy, m.REPLACEMENT) in message, (
            "the runnable statement and the message must be the same text, "
            "or this test is exercising a paraphrase")
        tx.execute(m.rename_sql(legacy, good))
        assert tx.execute(m.UNREGISTRABLE_SQL).fetchall() == [], (
            "the upgrade must be able to proceed after the operator does "
            "exactly what the refusal told them to do")
        assert tx.execute(
            "SELECT compartments FROM iam.app_user WHERE id = %s",
            (uid,)).fetchone()[0] == [good]
        assert tx.execute(
            'SELECT compartments FROM core."case" WHERE owner_user_id = %s',
            (uid,)).fetchone()[0] == [good]

        # An apostrophe is one of the ways to fail the key format, so a
        # value containing one is exactly the kind this code is printed
        # for. Python's repr() would quote it with DOUBLE quotes, which
        # Postgres reads as an identifier -- the refusal would hand the
        # operator a statement that fails with "column does not exist".
        quoted = "OP'X"
        tx.execute(
            "UPDATE iam.app_user SET compartments = %s WHERE id = %s",
            ([quoted], uid))
        assert [r[0] for r in tx.execute(m.UNREGISTRABLE_SQL).fetchall()] == [quoted]
        tx.execute(m.rename_sql(quoted, good))
        assert tx.execute(m.UNREGISTRABLE_SQL).fetchall() == []
        assert tx.execute(
            "SELECT compartments FROM iam.app_user WHERE id = %s",
            (uid,)).fetchone()[0] == [good]
    finally:
        tx.rollback()
        tx.close()


def test_a_case_edit_has_no_compartment_field_on_either_side(conn):
    """`PATCH /cases/{id}` deliberately cannot write compartments (its
    body docstring says why). This pins BOTH halves -- the router body and
    the service signature -- so that whoever adds the field to one must
    add it, and the registry check, to the other in the same change."""
    import inspect

    from noctornal_api.cases import CaseService
    from noctornal_api.http.routers.cases import UpdateCaseBody
    assert "compartments" not in UpdateCaseBody.model_fields
    assert "compartments" not in inspect.signature(
        CaseService.update_metadata).parameters
