"""Migration 0059: every compartment column is bound to `iam.compartment`.

0057 created the registry and made two SERVICE write sites check it. The
columns themselves stayed raw `text[]` (seventeen arrays and the scalar
`ingest.api_key.forced_compartment`), so until 2026-09-09 a psql typo, a
direct UPDATE, or a stealer-log key issued under an unregistered
compartment all succeeded, and every one of them was the silent
no-access the registry exists to end. Reproduced before this file was
written: `UPDATE iam.app_user SET compartments = '{OP-KESTRAL}'` was
accepted at 0058.

Each test here reads BOTH sides of a contract that crosses a file:

- the DATABASE refuses the write, and the FIRST LINE of its refusal --
  the only line `http/errors.safe_detail` forwards -- names the key, the
  column and the registration route;
- the registration route the message names EXISTS in the FastAPI route
  table, and the live trigger function's source carries the same text as
  the migration module's constant, so neither can drift from the other;
- the catalog's set of compartment columns equals the migration's
  `BOUND_COLUMNS` and every one carries the trigger, so a future column
  cannot be added unbound;
- the refusal reaches an HTTP client with the STATUS the service's own
  check produces (400 for a case or an ingest key, 409 for a read-in),
  which is the fact the migration relies on when it keeps the service
  checks as the readable error rather than the guarantee;
- the upgrade's refusal message is executable and, once run, lets the
  upgrade proceed -- proved on the real `alembic` command against the
  test database, not on a paraphrase.

Env-gated on DATABASE_URL. Email prefix `bind-`; registry keys `BIND-T9-`.
The round-trip test is last because it moves the schema.
"""
from __future__ import annotations

import importlib.util
import os
import re
import time
from datetime import date
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; binding tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
# Issuing an ingest key HMACs the secret with a pepper and refuses without
# one; the same stand-in every ingest test uses.
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

PASSWORD = "correct-horse-battery-staple-7"
EMAIL_LIKE = "bind-%@noctornal.test"
KEY_LIKE = "BIND-T9-%"
ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = ROOT / "db" / "migrations"
MIGRATION = MIGRATIONS / "versions" / "0059_compartments_registered.py"

#: The columns the work item names by hand; `BOUND_COLUMNS` in the
#: migration is the full set and `test_every_compartment_column_in_the_
#: catalog_carries_the_binding` holds it to the catalog.
NAMED = (
    "iam.app_user.compartments", "core.case.compartments",
    "core.node.compartments", "core.evidence.compartments",
    "ingest.record.compartments", "ingest.api_key.forced_compartment",
)


def _m0059():
    """The version file itself, loaded as a module, as the 0057 test does:
    a test that restates the migration's SQL proves the test agrees with
    the test."""
    spec = importlib.util.spec_from_file_location("m0059", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        # Rows that carry a BIND-T9 key go first: since 0059 the registry
        # refuses to drop a key that is still in use, so a teardown in the
        # wrong order would be refused by the thing it is cleaning up after.
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
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
    return f"BIND-T9-{uuid4().hex[:6].upper()}"


def _email() -> str:
    return f"bind-{uuid4().hex[:8]}@noctornal.test"


def _register(conn, key: str) -> None:
    conn.execute(
        "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
        "ON CONFLICT (key) DO NOTHING", (key, f"{key} (binding test)"))


def _user(conn, *global_roles, clearance="AMBER", compartments=()):
    """A login-capable account. Compartments are REGISTERED before the
    array is written, because since 0059 the raw UPDATE every fixture in
    this suite uses is itself bound -- which is what this file proves."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = _email()
    store = PgUserStore(conn)
    uid = store.create_user(email, "Bind", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    for key in compartments:
        _register(conn, key)
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


def _tx() -> psycopg.Connection:
    """A non-autocommit connection: everything a test does on it is rolled
    back, so the rows it seeds -- including the ones the binding refuses --
    never reach another test or the teardown."""
    from noctornal_api.db import dsn
    return psycopg.connect(dsn())


def _refused(tx, sql: str, params=()) -> str:
    """Run `sql` expecting the binding to refuse it, and return the FIRST
    LINE of the refusal -- the line `safe_detail` forwards to a client, so
    what this returns is what an operator would read. Fails the test if
    the statement is accepted, which is exactly what happened at 0058."""
    tx.execute("SAVEPOINT refused")
    try:
        tx.execute(sql, params)
    except psycopg.errors.RaiseException as exc:
        tx.execute("ROLLBACK TO SAVEPOINT refused")
        return str(exc).splitlines()[0]
    tx.execute("RELEASE SAVEPOINT refused")
    pytest.fail(f"accepted, but the binding must refuse it: {sql}")


def _seed_rows(tx) -> dict[str, tuple[str, str, object]]:
    """One row in each column the work item names, with the minimum the
    schema requires, keyed by the label the refusal message uses. Returns
    {label: (qualified table, column, id)}."""
    uid = tx.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash,
                                     tlp_clearance)
           VALUES (%s, 'Bind', 'x', 'RED') RETURNING id""",
        (_email(),)).fetchone()[0]
    case_id = tx.execute(
        """INSERT INTO core."case" (code, title, owner_user_id, legal_basis,
                                    retention_until, review_due)
           VALUES (%s, 'Bind', %s, 'production order', '2028-01-01',
                   '2027-01-01') RETURNING id""",
        (f"OP-BIND-{uuid4().hex[:6]}", uid)).fetchone()[0]
    node_id = tx.execute(
        """INSERT INTO core.node (case_id, node_type, label, created_by)
           VALUES (%s, 'IDENTITY', 'bind', %s) RETURNING id""",
        (case_id, uid)).fetchone()[0]
    tx.execute(
        """INSERT INTO core.assertion (case_id, node_id, basis, created_by)
           VALUES (%s, %s, 'DIRECT_OBSERVATION', %s)""",
        (case_id, node_id, uid))
    ev_id = tx.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, 'exhibit', 'text/plain', 1, %s, %s, %s, 'b', 'AMBER',
                   'MANUAL_UPLOAD', now(), %s) RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"bind/{uuid4().hex}",
         uid)).fetchone()[0]
    key_id = tx.execute(
        """INSERT INTO ingest.api_key (key_id, secret_hmac, pepper_id, name,
                                       expires_at, owner_user_id)
           VALUES (%s, %s, 'env:v1', 'bind', now() + interval '1 day', %s)
           RETURNING id""",
        (uuid4().hex[:8], os.urandom(32), uid)).fetchone()[0]
    batch_id = tx.execute(
        """INSERT INTO ingest.batch (api_key_id, raw_key, raw_bytes, raw_sha256)
           VALUES (%s, %s, 1, %s) RETURNING id""",
        (key_id, f"bind/{uuid4().hex}", os.urandom(32))).fetchone()[0]
    rec_id = tx.execute(
        """INSERT INTO ingest.record (batch_id, payload, content_sha256)
           VALUES (%s, '{}'::jsonb, %s) RETURNING id""",
        (batch_id, os.urandom(32))).fetchone()[0]
    return {
        "iam.app_user.compartments": ('iam."app_user"', "compartments", uid),
        "core.case.compartments": ('core."case"', "compartments", case_id),
        "core.node.compartments": ('core."node"', "compartments", node_id),
        "core.evidence.compartments": ('core."evidence"', "compartments", ev_id),
        "ingest.record.compartments": ('ingest."record"', "compartments", rec_id),
        "ingest.api_key.forced_compartment":
            ('ingest."api_key"', "forced_compartment", key_id),
    }


# --- the binding itself -----------------------------------------------------

def test_a_direct_write_of_an_unregistered_key_is_refused_on_every_named_column():
    """The work item's six columns, by direct UPDATE with no service in
    the way -- the psql path. Each is refused, the refusal's first line
    names the key, the column and the registration route, and registering
    the key is the ONLY thing that turns the same statement into a
    success. Fails at 0058, where every one of these UPDATEs succeeded."""
    m = _m0059()
    typo = _key()
    tx = _tx()
    try:
        rows = _seed_rows(tx)
        assert set(rows) == set(NAMED)
        for label, (table, column, row_id) in rows.items():
            value = typo if column == "forced_compartment" else [typo]
            first = _refused(
                tx, f"UPDATE {table} SET {column} = %s WHERE id = %s",
                (value, row_id))
            assert typo in first, (label, first)
            assert label in first, (label, first)
            assert m.REGISTRATION_ROUTE in first, (
                "the operator at a psql prompt has to be told where to "
                "register the key, on the one line safe_detail forwards")
            assert "user.manage" in first

        # INSERT is bound as well as UPDATE, and a NULL element is refused
        # as something that is not a key and can never be held.
        first = _refused(
            tx, """INSERT INTO iam.app_user (email, display_name,
                                             password_hash, compartments)
                   VALUES (%s, 'Bind', 'x', %s)""", (_email(), [typo]))
        assert typo in first
        held = _key()
        tx.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                   (held,))
        first = _refused(
            tx, "UPDATE iam.app_user SET compartments = %s WHERE id = %s",
            ([held, None], rows["iam.app_user.compartments"][2]))
        assert "NULL" in first and held not in first, (
            "only the element that is not registered is named")

        # A row with no compartment is untouched by the binding.
        tx.execute("UPDATE iam.app_user SET compartments = '{}' WHERE id = %s",
                   (rows["iam.app_user.compartments"][2],))
        tx.execute("UPDATE ingest.api_key SET forced_compartment = NULL "
                   "WHERE id = %s", (rows["ingest.api_key.forced_compartment"][2],))

        # Registered: the identical statements succeed.
        tx.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                   (typo,))
        for label, (table, column, row_id) in rows.items():
            value = typo if column == "forced_compartment" else [typo]
            tx.execute(f"UPDATE {table} SET {column} = %s WHERE id = %s",
                       (value, row_id))
            assert tx.execute(
                f"SELECT {column} FROM {table} WHERE id = %s", (row_id,)
            ).fetchone()[0] == value, label
    finally:
        tx.rollback()
        tx.close()


def test_every_compartment_column_in_the_catalog_carries_the_binding(conn):
    """Two halves that must agree: the catalog's compartment columns and
    the migration's `BOUND_COLUMNS`. A column in the catalog the tuple
    does not name is a column a future migration added unbound -- the
    hole re-opened -- and a tuple entry with no column is a claim the
    schema does not back. Then every bound column carries the trigger,
    installed BEFORE the write and only on writes of that column, and
    the registry carries its own guard."""
    m = _m0059()
    in_catalog = {tuple(r) for r in conn.execute(
        """SELECT table_schema, table_name, column_name
             FROM information_schema.columns
            WHERE column_name IN ('compartments', 'visibility_compartments',
                                  'forced_compartment')
              AND table_schema NOT IN ('pg_catalog', 'information_schema')"""
    ).fetchall()}
    bound = {(s, t, c) for s, t, c, _kind in m.BOUND_COLUMNS}
    assert in_catalog == bound, {
        "in the catalog but not bound": sorted(in_catalog - bound),
        "bound but not in the catalog": sorted(bound - in_catalog)}
    assert len(m.BOUND_COLUMNS) == 18

    for schema, table, column, kind in m.BOUND_COLUMNS:
        row = conn.execute(
            """SELECT pg_get_triggerdef(t.oid)
                 FROM pg_trigger t
                 JOIN pg_class c ON c.oid = t.tgrelid
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s AND t.tgname = %s""",
            (schema, table, m.TRIGGER_NAME)).fetchone()
        assert row is not None, f"{schema}.{table}.{column} is not bound"
        definition = row[0]
        assert "BEFORE INSERT OR UPDATE OF " + column in definition, definition
        assert "iam.refuse_unregistered_compartment(" in definition
        assert f"'{column}', '{kind}'" in definition, definition
        assert "WHEN (" in definition, (
            "a row with no compartment must not pay for the check")

    registry = conn.execute(
        """SELECT pg_get_triggerdef(t.oid) FROM pg_trigger t
            WHERE t.tgrelid = 'iam.compartment'::regclass AND t.tgname = %s""",
        (m.REGISTRY_TRIGGER_NAME,)).fetchone()
    assert registry is not None, "the registry side of the binding is missing"
    assert "BEFORE DELETE OR UPDATE OF key" in registry[0]

    # The predicate the triggers are built on, on its own terms.
    held = _key()
    _register(conn, held)
    q = "SELECT iam.compartments_registered(%s::text[])"
    assert conn.execute(q, ([held],)).fetchone()[0] is True
    assert conn.execute(q, ([],)).fetchone()[0] is True
    assert conn.execute(q, (None,)).fetchone()[0] is True
    assert conn.execute(q, ([held, _key()],)).fetchone()[0] is False
    assert conn.execute(q, ([held, None],)).fetchone()[0] is False


def test_the_registry_refuses_to_drop_or_rename_a_key_still_in_use():
    """The reverse half of "bound". Without it, `DELETE FROM
    iam.compartment` would orphan every row filed under the key and the
    next write to any of them would be refused by 0059's own trigger for
    a key that was real a moment ago. Relabelling stays allowed: the label
    is what a person reads, the key is what the gate compares."""
    key = _key()
    tx = _tx()
    try:
        rows = _seed_rows(tx)
        tx.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                   (key,))
        uid = rows["iam.app_user.compartments"][2]
        api_key = rows["ingest.api_key.forced_compartment"][2]
        tx.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                   ([key], uid))
        tx.execute("UPDATE ingest.api_key SET forced_compartment = %s "
                   "WHERE id = %s", (key, api_key))

        first = _refused(tx, "DELETE FROM iam.compartment WHERE key = %s", (key,))
        assert key in first
        assert "iam.app_user.compartments" in first, first
        assert "ingest.api_key.forced_compartment" in first, (
            "every column still carrying the key is named, so the operator "
            "knows what to rename or remove first")
        first = _refused(tx, "UPDATE iam.compartment SET key = %s WHERE key = %s",
                         (_key(), key))
        assert key in first
        tx.execute("UPDATE iam.compartment SET label = 'renamed' WHERE key = %s",
                   (key,))

        tx.execute("UPDATE iam.app_user SET compartments = '{}' WHERE id = %s",
                   (uid,))
        tx.execute("UPDATE ingest.api_key SET forced_compartment = NULL "
                   "WHERE id = %s", (api_key,))
        tx.execute("DELETE FROM iam.compartment WHERE key = %s", (key,))
        assert tx.execute("SELECT 1 FROM iam.compartment WHERE key = %s",
                          (key,)).fetchone() is None
    finally:
        tx.rollback()
        tx.close()


def test_the_refusal_names_a_registration_route_that_exists(conn):
    """The message tells an operator to `POST /api/v1/compartments`. Three
    places have to agree on that: the migration module's constant, the
    trigger function INSTALLED in the database (whose source is what an
    upgraded deployment actually runs), and the FastAPI route table."""
    from noctornal_api.http.app import create_app
    m = _m0059()
    method, path = m.REGISTRATION_ROUTE.split(" ", 1)
    # The OpenAPI document rather than `app.routes`: this FastAPI keeps an
    # included router as a lazy `_IncludedRouter` entry with no path of
    # its own, so walking `app.routes` sees `/healthz` and nothing else.
    paths = create_app().openapi()["paths"]
    assert path in paths, (m.REGISTRATION_ROUTE, sorted(paths))
    assert method.lower() in paths[path], (m.REGISTRATION_ROUTE, paths[path])
    installed = conn.execute(
        """SELECT p.prosrc FROM pg_proc p
             JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'iam'
              AND p.proname = 'refuse_unregistered_compartment'""").fetchone()
    assert installed is not None
    assert m.REGISTRATION_ROUTE in installed[0], (
        "the database names a different route from the module")


def test_the_three_readable_refusals_name_the_same_route_and_it_exists(conn):
    """One rule, three authored refusals -- the trigger's,
    `CaseService._require_registered`'s and
    `IamAdminService.set_compartments`'s -- each telling the operator
    where to register the key. Until 2026-09-09 the two service messages
    said `POST /compartments`, a path that exists nowhere (the router is
    mounted under `/api/v1`), while the trigger said
    `POST /api/v1/compartments`: two readable refusals for one rule that
    disagreed about the fix, and one of them wrong. Each message's route
    is held to the migration's constant AND to the OpenAPI route table,
    so neither service can drift from the trigger, or from the router,
    without failing here."""
    from noctornal_api.cases import CaseError, CaseService
    from noctornal_api.http.app import create_app
    from noctornal_api.iam_admin import AdminError, IamAdminService
    m = _m0059()
    paths = create_app().openapi()["paths"]
    admin_id, _, _ = _user(conn, "SYS_ADMIN")
    typo = _key()

    refusals = {}
    with pytest.raises(CaseError) as refused:
        CaseService(conn)._require_registered([typo])
    refusals["cases"] = str(refused.value)
    with pytest.raises(AdminError) as refused:
        IamAdminService(conn).set_compartments(admin_id, [typo], actor_id=admin_id)
    refusals["iam_admin"] = str(refused.value)
    tx = _tx()
    try:
        refusals["trigger"] = _refused(
            tx, "UPDATE iam.app_user SET compartments = %s WHERE id = %s",
            ([typo], admin_id))
    finally:
        tx.rollback()
        tx.close()

    route = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE) (/[A-Za-z0-9_./{}-]+)")
    for side, text in refusals.items():
        assert typo in text, (side, text)
        found = route.search(text)
        assert found, (side, "names no registration route at all", text)
        method, path = found.groups()
        assert f"{method} {path}" == m.REGISTRATION_ROUTE, (side, text)
        assert path in paths and method.lower() in paths[path], (side, path)


# --- the refusal on the wire ------------------------------------------------

def test_the_database_refusal_reaches_the_client_with_the_service_status(
        conn, client, monkeypatch):
    """The migration keeps the application-level checks as the readable
    error and calls the trigger the guarantee. That is only honest if the
    guarantee, when it is the one that fires, produces the same STATUS the
    check would have -- not a 500. Three services, three halves each:
    the service exception, the HTTP status, and the key named in both.

    For `cases` and `iam_admin` the service check is bypassed on purpose,
    which models the check drifting or being skipped by a future writer.
    For `ingest.issue_key` there is no service check at all: a stealer-log
    key under an unregistered compartment reached the INSERT, and before
    2026-09-09 that INSERT succeeded; today it is refused, and the
    refusal has to arrive as a 400 naming the key.
    """
    from noctornal_api.cases import CaseService
    from noctornal_api.iam_admin import AdminError, IamAdminService
    from noctornal_api.ingest import IngestError, IngestService

    # -- ingest: no bypass needed ------------------------------------------
    admin_id, admin_email, admin_secret = _user(conn, "SYS_ADMIN", clearance="RED")
    admin = _login(client, admin_email, admin_secret)
    typo = _key()
    r = client.post("/api/v1/ingest/keys", headers=_auth(admin), json={
        "name": "stealer feed (binding test)", "declared_category": "STEALER_LOG",
        "forced_compartment": typo})
    assert r.status_code == 400, r.text
    assert typo in r.text and "regist" in r.text, r.text
    assert r.headers["content-type"].startswith("application/problem+json")
    assert conn.execute(
        "SELECT count(*) FROM ingest.api_key WHERE forced_compartment = %s",
        (typo,)).fetchone()[0] == 0
    with pytest.raises(IngestError, match=typo):
        IngestService(conn).issue_key(
            name="stealer feed (service)", owner_user_id=admin_id,
            declared_category="STEALER_LOG", forced_compartment=typo)
    made = client.post("/api/v1/compartments", headers=_auth(admin),
                       json={"key": typo, "label": "Stealer (binding test)"})
    assert made.status_code == 201, made.text
    r = client.post("/api/v1/ingest/keys", headers=_auth(admin), json={
        "name": "stealer feed (binding test)", "declared_category": "STEALER_LOG",
        "forced_compartment": typo})
    assert r.status_code == 201, r.text
    assert conn.execute(
        "SELECT forced_compartment FROM ingest.api_key WHERE id = %s",
        (r.json()["id"],)).fetchone()[0] == typo

    # -- cases: the service checks bypassed, the database still refuses ---
    owner_id, owner_email, owner_secret = _user(conn, "CASE_OWNER")
    owner = _login(client, owner_email, owner_secret)
    monkeypatch.setattr(CaseService, "_require_registered",
                        lambda self, compartments: None)
    monkeypatch.setattr(CaseService, "_require_compartments",
                        lambda self, user_id, compartments, who: None)
    typo = _key()
    r = client.post("/api/v1/cases", headers=_auth(owner), json={
        "code": f"OP-BIND-{uuid4().hex[:6]}", "title": "Bound",
        "legal_basis": "production order 2026-0007",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)), "compartments": [typo]})
    assert r.status_code == 400, r.text
    assert typo in r.text and "regist" in r.text, r.text
    assert "(ref " in r.text, "a database-sourced detail carries its correlation id"
    assert conn.execute(
        'SELECT count(*) FROM core."case" WHERE owner_user_id = %s',
        (owner_id,)).fetchone()[0] == 0

    # -- iam_admin: the service check bypassed, the database still refuses
    monkeypatch.setattr(IamAdminService, "_unknown_compartments",
                        lambda self, keys: [])
    typo = _key()
    with pytest.raises(AdminError, match=typo):
        IamAdminService(conn).set_compartments(owner_id, [typo], actor_id=admin_id)
    r = client.put(f"/api/v1/compartments/users/{owner_id}", headers=_auth(admin),
                   json={"compartments": [typo]})
    assert r.status_code == 409, r.text
    assert typo in r.text, r.text
    assert conn.execute(
        "SELECT compartments FROM iam.app_user WHERE id = %s", (owner_id,)
    ).fetchone()[0] == [], "a refused write must change nothing"


# --- the migration ------------------------------------------------------------

def _unbound(tx) -> None:
    """Model the database an upgrade to 0059 actually finds: one where the
    binding does not exist yet and an unregistered value can be in use.
    `DISABLE TRIGGER USER` is the suite's idiom for this (see
    `test_audit_verify_pg.py`); it is transactional, so the rollback that
    ends every such test also re-enables the trigger."""
    tx.execute("ALTER TABLE iam.app_user DISABLE TRIGGER USER")
    tx.execute("ALTER TABLE ingest.api_key DISABLE TRIGGER USER")


def test_the_upgrade_refuses_an_unregistered_value_with_a_runnable_cleanup():
    """0059 refuses an in-use value the registry does not hold and prints,
    per value, the three statements the operator can choose between. As
    with 0057, the refusal is only honest if the statements RUN and leave
    the pre-check empty. Seeded in a rolled-back transaction with the
    binding disabled, because at head the binding would refuse the seed.

    Four values, one of each kind the cleanup has to handle: a
    format-valid key in an array AND in the scalar, a NULL element, and a
    value the key format cannot take.
    """
    m = _m0059()
    valid, held, good = _key(), _key(), _key()
    tx = _tx()
    try:
        _unbound(tx)
        rows = _seed_rows(tx)
        uid = rows["iam.app_user.compartments"][2]
        api_key = rows["ingest.api_key.forced_compartment"][2]
        tx.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                   (held,))
        tx.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                   ([valid, held, None, "bad key"], uid))
        tx.execute("UPDATE ingest.api_key SET forced_compartment = %s WHERE id = %s",
                   (valid, api_key))

        found = tx.execute(m.UNREGISTERED_SQL).fetchall()
        mine = [(v, c) for v, c in found
                if v in (valid, None, "bad key")]
        # A set: the statement orders by the database's collation, under
        # which 'bad key' sorts before 'BIND-...', and the order is not
        # part of the contract -- every (value, column) pair is.
        assert set(mine) == {
            (valid, "iam.app_user.compartments"),
            (valid, "ingest.api_key.forced_compartment"),
            ("bad key", "iam.app_user.compartments"),
            (None, "iam.app_user.compartments"),
        }, mine
        assert len(mine) == 4, "one row per (value, column), not per holder"
        assert held not in [v for v, _ in found]

        message = m.refusal_message(mine)
        assert f"'{valid}'" in message and "'bad key'" in message
        assert "NULL" in message
        assert "ingest.api_key.forced_compartment" in message
        assert m.REPLACEMENT in message and m.REGISTRATION_ROUTE in message
        # The runnable statements and the message are the same text.
        cols = ["iam.app_user.compartments", "ingest.api_key.forced_compartment"]
        assert m.register_sql(valid) in message
        assert m.rename_sql(valid, m.REPLACEMENT, cols) in message
        assert m.remove_sql(valid, cols) in message
        assert m.remove_sql(None, ["iam.app_user.compartments"]) in message
        assert m.register_sql("bad key") not in message, (
            "a value the format rejects must not be offered for registration")
        assert "DECLASSIF" in message

        # Remedy 1, rename: the value leaves every column that held it.
        tx.execute(m.rename_sql(valid, good, cols))
        tx.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                   (good,))
        left = {v for v, _ in tx.execute(m.UNREGISTERED_SQL).fetchall()}
        assert valid not in left and good not in left
        assert tx.execute("SELECT forced_compartment FROM ingest.api_key "
                          "WHERE id = %s", (api_key,)).fetchone()[0] == good
        # Remedy 2, remove: the NULL element and the unregistrable value.
        tx.execute(m.remove_sql(None, ["iam.app_user.compartments"]))
        tx.execute(m.remove_sql("bad key", ["iam.app_user.compartments"]))
        left = {v for v, _ in tx.execute(m.UNREGISTERED_SQL).fetchall()}
        assert None not in left and "bad key" not in left
        assert tx.execute("SELECT compartments FROM iam.app_user WHERE id = %s",
                          (uid,)).fetchone()[0] == [good, held]
        # Remedy 3, register: offered only for a value the format allows.
        again = _key()
        tx.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                   ([again], uid))
        assert again in {v for v, _ in tx.execute(m.UNREGISTERED_SQL).fetchall()}
        tx.execute(m.register_sql(again))
        tx.execute(m.register_sql(again))  # idempotent
        assert again not in {v for v, _ in tx.execute(m.UNREGISTERED_SQL).fetchall()}
    finally:
        tx.rollback()
        tx.close()


def _alembic():
    from alembic.config import Config
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(MIGRATIONS))
    return cfg


def _version(conn) -> str:
    return conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]


def _chain_head() -> str:
    """The head Alembic would upgrade to, read from the scripts.

    The round trip below used to name 0059 as the place it returns to.
    That is the revision it was written against, not the thing it is
    testing, and 0060 made the literal wrong -- the test skipped, and
    the build fails on a skip.
    """
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(_alembic()).get_current_head()


def _binding_count(conn) -> int:
    return conn.execute(
        """SELECT count(*) FROM pg_trigger
            WHERE tgname IN ('compartments_registered', 'compartment_in_use')
              AND NOT tgisinternal""").fetchone()[0]


def test_downgrade_to_0058_and_upgrade_to_head_round_trip(conn):
    """The real `alembic` command, both directions, on the test database.

    On the way back up, the refusal is exercised for real rather than by
    running its pieces: at 0058 the old hole is open again, so a user is
    read into an unregistered key by direct UPDATE (which succeeds, as it
    did before 2026-09-09), the upgrade is asked to run, and it must stop
    with the message that names the value and the column and prints the
    statement that fixes it. That statement is then run, and the upgrade
    completes.

    Guarded so a failure cannot leave the schema behind: it runs only
    when the database is AT THE CHAIN HEAD -- wherever that is, so a new
    migration does not switch this off -- and only when the pre-check is
    already empty (otherwise the upgrade would refuse for reasons this
    test did not create). The `finally` puts the schema back to head
    whatever happened in between.

    It used to demand exactly 0059 and skip otherwise, on the reasoning
    that a later migration's test owns its own round trip. That is not a
    rule that holds: what is exercised here is 0059's refusal across
    0058's boundary, which no later migration inherits, and the skip
    fails the build anyway because CI refuses a skipped test. Migration
    0060 is what proved it, by turning this green test into a red
    pipeline that named neither.
    """
    from alembic import command
    m = _m0059()
    head = _chain_head()
    assert _version(conn) == head, (
        f"the database is at {_version(conn)} and the chain head is {head}; "
        "run `alembic upgrade head` before this suite, because the round "
        "trip below has to know where to put the schema back")
    assert conn.execute(m.UNREGISTERED_SQL).fetchall() == [], (
        "the database already holds an unregistered value; the upgrade "
        "would refuse for it, so clean it up before running this test")
    assert _binding_count(conn) == len(m.BOUND_COLUMNS) + 1
    cfg = _alembic()
    typo, good = _key(), _key()
    try:
        command.downgrade(cfg, "0058")
        assert _version(conn) == "0058"
        assert _binding_count(conn) == 0
        assert conn.execute(
            "SELECT count(*) FROM pg_proc WHERE proname IN "
            "('compartments_registered', 'unregistered_compartments', "
            "'refuse_unregistered_compartment', 'compartment_in_use', "
            "'refuse_compartment_removal')").fetchone()[0] == 0

        # The hole, open again: this is the write the binding exists for.
        uid = conn.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash,
                                         compartments)
               VALUES (%s, 'Legacy', 'x', %s) RETURNING id""",
            (_email(), [typo])).fetchone()[0]

        with pytest.raises(RuntimeError) as refused:
            command.upgrade(cfg, "head")
        message = str(refused.value)
        assert f"'{typo}'" in message and "iam.app_user.compartments" in message
        assert m.rename_sql(typo, m.REPLACEMENT, ["iam.app_user.compartments"]) in message
        assert _version(conn) == "0058", "a refused upgrade changes nothing"
        assert _binding_count(conn) == 0

        # Do exactly what the message says, then the upgrade completes.
        _register(conn, good)
        conn.execute(m.rename_sql(typo, good, ["iam.app_user.compartments"]))
        assert conn.execute("SELECT compartments FROM iam.app_user WHERE id = %s",
                            (uid,)).fetchone()[0] == [good]
        command.upgrade(cfg, "head")
        assert _version(conn) == head
        assert _binding_count(conn) == len(m.BOUND_COLUMNS) + 1
        # And the hole is closed again on the row the upgrade found.
        with pytest.raises(psycopg.errors.RaiseException, match=typo):
            conn.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                         ([typo], uid))
    finally:
        if _version(conn) != head:
            conn.execute("DELETE FROM iam.app_user WHERE email LIKE %s",
                         (EMAIL_LIKE,))
            command.upgrade(cfg, "head")
