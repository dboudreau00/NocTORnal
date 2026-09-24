"""Renaming and retiring a registered compartment key
(sec-compartment-retirement, 2026-09-23).

Before this there was no product route to do either: 0059's registry
trigger refuses to drop or rename a key while any row carries it, so a
mistyped key was permanent short of a hand-written UPDATE on each of
eighteen columns. Each test here would fail on the base commit (245cb57)
for the plainest reason, a 404 or 405 from a route that did not exist.

What is held:

- the service's column list is migration 0059's, and the live triggers';
- a rename moves every carrier at once, in one transaction, keeps the
  label and the registration, and changes no access decision: the analyst
  read into the old key still opens the case filed under it;
- a rename onto a registered key (a merge), to a malformed key, of an
  unknown key, without `user.manage` or without a fresh step-up, is
  refused and changes nothing;
- retiring a key nothing carries removes it; retiring one still carried
  is refused, naming the accounts and cases by name and the rest by
  count, and changes nothing;
- both are audited in the transaction that makes the change;
- the bound tables are locked while it runs, so a write in flight makes
  it wait, and give up as busy, rather than leave a row behind carrying a
  key the registry no longer holds.

Env-gated on DATABASE_URL. Email prefix `cml-`; registry keys `CML-T1-`.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import date
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; lifecycle tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

PASSWORD = "correct-horse-battery-staple-7"
EMAIL_LIKE = "cml-%@noctornal.test"
KEY_LIKE = "CML-T1-%"
ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "db" / "migrations" / "versions" / "0059_compartments_registered.py"


def _m0059():
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
        # Carriers first: the registry refuses to drop a key still in use.
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
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
    return f"CML-T1-{uuid4().hex[:6].upper()}"


def _register(conn, key: str, label: str | None = None) -> None:
    conn.execute(
        "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
        "ON CONFLICT (key) DO NOTHING", (key, label or f"{key} (lifecycle test)"))


def _user(conn, *roles, clearance="AMBER", compartments=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"cml-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Cml", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    for key in compartments:
        _register(conn, key)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
        "WHERE id = %s", (clearance, list(compartments), uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid, email


def _auth(conn, email, *, fresh=True) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=fresh)
    return {"Authorization": f"Bearer {token}"}


def _estate(conn, client, key):
    """Something filed under `key` in five of the eighteen columns: an
    owner and an analyst read into it, a case filed under it, an entity
    and an exhibit in that case, and a stealer-log ingest key forcing it.
    Returns what the assertions need."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.ingest import IngestService
    _register(conn, key, "Kestrel (lifecycle test)")
    owner, owner_email = _user(conn, "CASE_OWNER", clearance="RED",
                               compartments=(key,))
    analyst, analyst_email = _user(conn, compartments=(key,))
    code = f"OP-CML-{uuid4().hex[:6].upper()}"
    r = client.post("/api/v1/cases", headers=_auth(conn, owner_email), json={
        "code": code, "title": "Operation CML",
        "legal_basis": "production order 2026-0923",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)),
        "classification": "AMBER", "compartments": [key]})
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, 'ANALYST', %s)", (case_id, analyst, owner))
    node = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label="cml_entity",
        classification="AMBER", compartments=[key], created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner))
    exhibit = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification, compartments,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, 'log.txt', 'text/plain', 8, %s, %s, %s, 'test-bucket',
                   'AMBER', %s, 'MANUAL_UPLOAD', now(), %s)
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"k/{uuid4().hex}", [key],
         owner)).fetchone()[0]
    issued = IngestService(conn).issue_key(
        name="stealer feed (lifecycle test)", owner_user_id=owner,
        declared_category="STEALER_LOG", forced_compartment=key)
    api_key = issued.id
    return {"owner": owner, "analyst": analyst, "analyst_email": analyst_email,
            "owner_email": owner_email, "case_id": case_id, "code": code,
            "node": node, "exhibit": exhibit, "api_key": api_key}


def _admin(conn, *, fresh=True) -> dict:
    _uid, email = _user(conn, "SYS_ADMIN", clearance="RED")
    return _auth(conn, email, fresh=fresh)


def _carriers(conn, key) -> dict[str, int]:
    from noctornal_api.compartment_lifecycle import CompartmentLifecycle
    return {c.column: c.rows for c in CompartmentLifecycle(conn).where_carried(key)}


def _audits(conn, action, field, value) -> list[dict]:
    return [r[0] for r in conn.execute(
        "SELECT detail FROM audit.event WHERE action = %s "
        "  AND detail->>%s = %s", (action, field, value)).fetchall()]


# ---------------------------------------------------------------------------
# The column list
# ---------------------------------------------------------------------------

def test_the_service_moves_exactly_the_columns_0059_binds(conn):
    """A column the service does not know would be left behind by a rename
    (the final drop would then refuse, and nothing would change), so the
    list is held to the migration that installed the triggers and to the
    triggers themselves."""
    from noctornal_api.compartment_lifecycle import BOUND_COLUMNS, NOUNS
    assert BOUND_COLUMNS == _m0059().BOUND_COLUMNS
    live = set()
    for schema, table, args in conn.execute(
            """SELECT n.nspname, k.relname, t.tgargs
                 FROM pg_trigger t
                 JOIN pg_class k ON k.oid = t.tgrelid
                 JOIN pg_namespace n ON n.oid = k.relnamespace
                WHERE t.tgname = 'compartments_registered'
                  AND NOT t.tgisinternal""").fetchall():
        column, kind = bytes(args).split(b"\x00")[:2]
        live.add((schema, table, column.decode(), kind.decode()))
    assert live == set(BOUND_COLUMNS)
    assert set(NOUNS) == {(s, t) for s, t, _c, _k in BOUND_COLUMNS}


# ---------------------------------------------------------------------------
# Rename
# ---------------------------------------------------------------------------

def test_a_rename_moves_every_carrier_and_changes_no_access(conn, client):
    old, new = _key(), _key()
    e = _estate(conn, client, old)
    before = _carriers(conn, old)
    assert set(before) >= {
        "iam.app_user.compartments", "core.case.compartments",
        "core.node.compartments", "core.evidence.compartments",
        "ingest.api_key.forced_compartment"}
    analyst = _auth(conn, e["analyst_email"])
    case = f"/api/v1/cases/{e['case_id']}"
    assert client.get(case, headers=analyst).status_code == 200

    r = client.post(f"/api/v1/compartments/{old}/rename", headers=_admin(conn),
                    json={"new_key": new})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["key"] == new and out["previous_key"] == old
    assert out["label"] == "Kestrel (lifecycle test)", "the label is kept"
    assert out["rows"] == before
    assert out["total"] == sum(before.values())
    assert out["summary"].startswith(f"Renamed {old} to {new} everywhere")
    assert "2 accounts read in" in out["summary"]
    for bad in (chr(0x2014), chr(0x2013), " -- ", "(s)"):
        assert bad not in out["summary"]

    # Nothing carries the old key; the same rows carry the new one.
    assert _carriers(conn, old) == {}
    assert _carriers(conn, new) == before
    keys = {r[0] for r in conn.execute(
        "SELECT key FROM iam.compartment WHERE key IN (%s, %s)",
        (old, new)).fetchall()}
    assert keys == {new}
    assert conn.execute(
        'SELECT compartments FROM core."case" WHERE id = %s',
        (e["case_id"],)).fetchone()[0] == [new]
    assert conn.execute(
        "SELECT forced_compartment FROM ingest.api_key WHERE id = %s",
        (e["api_key"],)).fetchone()[0] == new

    # The lock has a new name and the same holders.
    assert client.get(case, headers=analyst).status_code == 200
    got = client.get(f"{case}/nodes/{e['node']}", headers=analyst)
    assert got.status_code == 200, got.text

    audit = _audits(conn, "COMPARTMENT_RENAMED", "from", old)
    assert len(audit) == 1
    assert audit[0]["to"] == new and audit[0]["rows"] == before


def test_a_new_label_can_come_with_the_rename(conn, client):
    old, new = _key(), _key()
    _register(conn, old)
    r = client.post(f"/api/v1/compartments/{old}/rename", headers=_admin(conn),
                    json={"new_key": new, "label": "Kestrel, renamed"})
    assert r.status_code == 200, r.text
    assert r.json()["summary"] == (
        f"Renamed {old} to {new}. Nothing was filed under it yet, so only "
        f"the registry changed.")
    assert conn.execute("SELECT label FROM iam.compartment WHERE key = %s",
                        (new,)).fetchone()[0] == "Kestrel, renamed"


def test_rename_refusals_change_nothing(conn, client):
    old, taken = _key(), _key()
    e = _estate(conn, client, old)
    _register(conn, taken)
    before = _carriers(conn, old)
    admin = _admin(conn)
    url = f"/api/v1/compartments/{old}/rename"

    merged = client.post(url, headers=admin, json={"new_key": taken})
    assert merged.status_code == 409, merged.text
    detail = merged.json()["detail"]
    assert taken in detail and "merge" in detail

    for bad in ("op-lower", "X", "SPACE KEY", "A" * 33):
        r = client.post(url, headers=admin, json={"new_key": bad})
        assert r.status_code == 409, (bad, r.text)
        assert "not a valid compartment key" in r.json()["detail"]
    same = client.post(url, headers=admin, json={"new_key": old})
    assert same.status_code == 409 and "nothing to rename" in same.json()["detail"]

    missing = client.post(f"/api/v1/compartments/{_key()}/rename",
                          headers=admin, json={"new_key": _key()})
    assert missing.status_code == 404, missing.text

    # Not an administrator: the Lead investigator who owns the case.
    owner = client.post(url, headers=_auth(conn, e["owner_email"]),
                        json={"new_key": _key()})
    assert owner.status_code == 403, owner.text
    # An administrator whose step-up has lapsed.
    stale = client.post(url, headers=_admin(conn, fresh=False),
                        json={"new_key": _key()})
    assert stale.status_code == 403, stale.text

    assert _carriers(conn, old) == before
    assert _audits(conn, "COMPARTMENT_RENAMED", "from", old) == []


def test_a_write_in_flight_makes_a_rename_wait_and_give_up(conn, client,
                                                           monkeypatch):
    """The lock. A transaction that has written to a bound table and not
    committed holds a lock the rename's SHARE ROW EXCLUSIVE conflicts
    with, so the rename waits for it, and after the timeout is refused as
    busy with nothing changed. Without the lock it would run straight
    past, and a row that transaction filed under the old key would commit
    after the key had gone."""
    from noctornal_api import compartment_lifecycle
    from noctornal_api.db import connect
    monkeypatch.setattr(compartment_lifecycle, "LOCK_TIMEOUT", "1s")
    old, new = _key(), _key()
    e = _estate(conn, client, old)
    before = _carriers(conn, old)
    other = connect()
    try:
        other.execute("BEGIN")
        other.execute(
            "UPDATE core.node SET label = 'cml_in_flight' WHERE id = %s",
            (e["node"],))
        r = client.post(f"/api/v1/compartments/{old}/rename",
                        headers=_admin(conn), json={"new_key": new})
        assert r.status_code == 409, r.text
        assert r.json()["title"] == "Busy"
        assert r.headers.get("Retry-After") == "30"
        assert "Nothing was changed" in r.json()["detail"]
    finally:
        other.execute("ROLLBACK")
        other.close()
    assert _carriers(conn, old) == before
    assert conn.execute("SELECT 1 FROM iam.compartment WHERE key = %s",
                        (new,)).fetchone() is None


# ---------------------------------------------------------------------------
# Retire
# ---------------------------------------------------------------------------

def test_a_key_nothing_carries_is_retired(conn, client):
    key = _key()
    _register(conn, key, "Registered by mistake")
    r = client.post(f"/api/v1/compartments/{key}/retire", headers=_admin(conn))
    assert r.status_code == 200, r.text
    assert r.json() == {"key": key, "label": "Registered by mistake",
                        "retired": True}
    assert conn.execute("SELECT 1 FROM iam.compartment WHERE key = %s",
                        (key,)).fetchone() is None
    assert len(_audits(conn, "COMPARTMENT_RETIRED", "key", key)) == 1
    again = client.post(f"/api/v1/compartments/{key}/retire",
                        headers=_admin(conn))
    assert again.status_code == 404, again.text


def test_a_carried_key_is_refused_naming_where(conn, client):
    """The administrator here is SYS_ADMIN at RED and on no case, which is
    how an administrator is set up: accounts and ingest keys are named
    (they list both elsewhere), the case is counted and not named."""
    key = _key()
    e = _estate(conn, client, key)
    r = client.post(f"/api/v1/compartments/{key}/retire", headers=_admin(conn))
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    emails = sorted([e["owner_email"], e["analyst_email"]])
    assert f"2 accounts read in ({', '.join(emails)})" in detail
    assert "; 1 case, which you cannot open;" in detail
    assert e["code"] not in detail
    assert "1 entity" in detail and "1 exhibit" in detail
    assert "1 ingest key (stealer feed (lifecycle test))" in detail
    assert "Read those accounts out of it on their cards under Accounts." in detail
    assert "a case's compartments are fixed when it is opened" in detail
    assert "rename it instead" in detail
    for bad in (chr(0x2014), chr(0x2013), " -- ", "(s)"):
        assert bad not in detail
    assert conn.execute("SELECT 1 FROM iam.compartment WHERE key = %s",
                        (key,)).fetchone() is not None
    assert _audits(conn, "COMPARTMENT_RETIRED", "key", key) == []


def test_a_key_only_accounts_hold_says_to_read_them_out_first(conn, client):
    key = _key()
    _user(conn, compartments=(key,))
    r = client.post(f"/api/v1/compartments/{key}/retire", headers=_admin(conn))
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "1 account read in (cml-" in detail
    assert detail.endswith(
        "Read that account out of it on its card under Accounts, then retire it.")


def _case(conn, client, owner_email, key, classification) -> str:
    code = f"OP-CML-{uuid4().hex[:6].upper()}"
    r = client.post("/api/v1/cases", headers=_auth(conn, owner_email), json={
        "code": code, "title": "Operation CML, second",
        "legal_basis": "production order 2026-0923",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)),
        "classification": classification, "compartments": [key]})
    assert r.status_code == 201, r.text
    return code


def test_the_refusal_names_no_case_the_administrator_cannot_open(conn, client):
    """Verifier, sec-compartment-retirement (2026-09-23): the refusal named
    up to five case codes to ANY `user.manage` holder, so a GREEN
    administrator retiring a key was told the code of a RED compartmented
    case they could not open, which no other surface in the product
    does. A case is named now only when it is in the caller's own case
    list; the rest are counted, and the refusal says why."""
    key = _key()
    e = _estate(conn, client, key)                     # an AMBER case
    red = _case(conn, client, e["owner_email"], key, "RED")
    url = f"/api/v1/compartments/{key}/retire"

    # The verifier's administrator: GREEN, read into the key, on no case.
    _uid, green = _user(conn, "SYS_ADMIN", clearance="GREEN",
                        compartments=(key,))
    r = client.post(url, headers=_auth(conn, green))
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "; 2 cases, none of which you can open;" in detail
    assert e["code"] not in detail and red not in detail

    # Assigned to the AMBER case at AMBER: that one is named, the RED one
    # (above their clearance) is counted.
    uid, amber = _user(conn, "SYS_ADMIN", clearance="AMBER",
                       compartments=(key,))
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
        (e["case_id"], uid, e["owner"]))
    detail = client.post(url, headers=_auth(conn, amber)).json()["detail"]
    assert f"; 2 cases ({e['code']}, and 1 you cannot open);" in detail
    assert red not in detail

    # The Lead investigator who owns both, made an administrator too: both
    # are in their case list, so both are named.
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'SYS_ADMIN')", (e["owner"],))
    detail = client.post(url, headers=_auth(conn, e["owner_email"])).json()[
        "detail"]
    assert f"; 2 cases ({', '.join(sorted([e['code'], red]))});" in detail

    for bad in (chr(0x2014), chr(0x2013), " -- ", "(s)"):
        assert bad not in detail
    assert conn.execute("SELECT 1 FROM iam.compartment WHERE key = %s",
                        (key,)).fetchone() is not None


def test_names_follow_what_the_caller_lists_elsewhere(conn, client):
    """The service's own rule, below the route: without a viewer nothing is
    named; accounts need `user.manage` and ingest keys `ingest.manage`,
    the verbs that list them by name elsewhere in the console."""
    from noctornal_api.compartment_lifecycle import (
        CompartmentInUse,
        CompartmentLifecycle,
    )
    key = _key()
    e = _estate(conn, client, key)
    life = CompartmentLifecycle(conn)

    anonymous = {c.column: c for c in life.where_carried(key)}
    assert all(not c.names for c in anonymous.values())
    assert anonymous["core.case.compartments"].phrase() == (
        "1 case, which you cannot open")

    # The analyst on the case: it is in their list, so it is named; they
    # hold neither admin verb, so accounts and the ingest key are counted.
    seen = {c.column: c for c in life.where_carried(key,
                                                    viewer_id=e["analyst"])}
    assert seen["core.case.compartments"].phrase() == f"1 case ({e['code']})"
    assert seen["iam.app_user.compartments"].phrase() == (
        "2 accounts read in, none of which you can list")
    assert seen["ingest.api_key.forced_compartment"].phrase() == (
        "1 ingest key, which you cannot list")
    assert seen["core.node.compartments"].phrase() == "1 entity"

    said = str(CompartmentInUse(key, list(seen.values())))
    assert e["owner_email"] not in said and "stealer feed" not in said


def test_the_phrase_counts_what_it_does_not_name():
    from noctornal_api.compartment_lifecycle import Carrier
    many = tuple(f"OP-{i}" for i in range(5))
    shown = ", ".join(many)
    assert Carrier("c", "case", "cases", 7, many, 7, "open").phrase() == (
        f"7 cases ({shown}, and 2 more)")
    assert Carrier("c", "case", "cases", 9, many, 7, "open").phrase() == (
        f"9 cases ({shown}, and 4 more, including 2 you cannot open)")
    assert Carrier("c", "case", "cases", 3, ("OP-1",), 1, "open").phrase() == (
        "3 cases (OP-1, and 2 you cannot open)")
    assert Carrier("c", "entity", "entities", 1).phrase() == "1 entity"


def test_retire_needs_user_manage_and_a_fresh_step_up(conn, client):
    key = _key()
    _register(conn, key)
    _uid, analyst = _user(conn, "ANALYST")
    url = f"/api/v1/compartments/{key}/retire"
    assert client.post(url, headers=_auth(conn, analyst)).status_code == 403
    assert client.post(url, headers=_admin(conn, fresh=False)).status_code == 403
    assert conn.execute("SELECT 1 FROM iam.compartment WHERE key = %s",
                        (key,)).fetchone() is not None
