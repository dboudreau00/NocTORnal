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

    # Any authenticated user can read the vocabulary -- it is the list an
    # analyst needs in order to ask for the right read-in, and a key is
    # not a secret (a case's contents are).
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

def _backfill_sql() -> str:
    spec = importlib.util.spec_from_file_location("m0057", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.BACKFILL_SQL


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
