"""Deployment configuration and a person's delivery settings are read-only
to the request role (0179, 0182).

The request role reads every configuration table and writes none of them,
bound or not, and the system role keeps every write. The administration
routes and the settings route write on a system connection after their own
gate; the unauthenticated ingest submit stamps a key's use through
`ingest.api_key_used`, which only a caller holding the key's secret can make
answer yes. Run as the request role, and over HTTP in production's shape
(NOCTORNAL_TEST_ASSUME_ROLE). Account, key, source and profile prefix
`rlscfg-`.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest

import collection_helpers as h
import egress_support as es
import rls_support as s

pytestmark = s.GATED

os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

P = "rlscfg-"
ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"


def _migration(prefix: str = "0179"):
    path = next(VERSIONS.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{prefix}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _writes() -> dict[str, tuple[str, ...]]:
    """Every write 0179 and 0182 took from the request role."""
    writes = dict(_migration("0179").CONFIG_WRITES)
    for table in _migration("0182").RUNTIME_READ_ONLY_TABLES:
        writes[table] = ("INSERT", "UPDATE", "DELETE")
    return writes


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {users}")
    c.execute(f"DELETE FROM notify.preference WHERE user_id IN {users}")
    h.teardown(c, P)
    es.teardown(c, P)
    s.cleanup(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def api(owner, monkeypatch):
    from noctornal_api.http.routers import collection as router

    es.clear_egress_env(monkeypatch)
    for key, value in es.keys().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(router, "blocking_failures", lambda _conn: [])
    client, app = h.client()
    return SimpleNamespace(client=client, app=app)


def _first_column(conn, table: str) -> str:
    return conn.execute(
        """SELECT quote_ident(attname) FROM pg_attribute
            WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped
            ORDER BY attnum LIMIT 1""", (table,)).fetchone()[0]


def _write(conn, table: str, privilege: str) -> str:
    """A statement that needs `privilege` on `table` and changes nothing
    when it is held: the privilege is checked before any row is read."""
    return {"INSERT": f"INSERT INTO {table} DEFAULT VALUES",
            "UPDATE": f"UPDATE {table} SET {_first_column(conn, table)} = DEFAULT "
                      f"WHERE false",
            "DELETE": f"DELETE FROM {table} WHERE false"}[privilege]


def _issue(owner, issuer, **over):
    from noctornal_api.ingest import IngestService
    return IngestService(owner).issue_key(name=f"{P}feed", owner_user_id=issuer, **over)


def _last_used(owner, key_id):
    return owner.execute("SELECT last_used_at FROM ingest.api_key WHERE id = %s",
                         (key_id,)).fetchone()[0]


@pytest.mark.parametrize("bound", [False, True], ids=["unbound", "bound"])
def test_no_configuration_table_takes_a_write_from_the_request_role(owner, bound):
    uid = s.user(owner, "RED", prefix=P)
    s.grant_global(owner, uid, "SYS_ADMIN")
    _sid, raw = s.session(owner, uid)
    app = s.app_conn(raw if bound else None)
    try:
        for table, privileges in _writes().items():
            for privilege in privileges:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    app.execute(_write(owner, table, privilege))
            # Every reader the request path has is untouched.
            app.execute(f"SELECT count(*) FROM {table}").fetchone()
    finally:
        app.close()


def test_the_system_role_keeps_every_write_it_held(owner):
    for table, privileges in _writes().items():
        for privilege in privileges:
            assert owner.execute("SELECT has_table_privilege(%s, %s, %s)",
                                 (s.WORKER_ROLE, table, privilege)).fetchone()[0], (
                table, privilege)
            assert not owner.execute("SELECT has_table_privilege(%s, %s, %s)",
                                     (s.APP_ROLE, table, privilege)).fetchone()[0], (
                table, privilege)


def test_a_key_is_stamped_only_by_a_caller_holding_its_secret(owner):
    from noctornal_api.ingest import KEY_PATTERN, IngestService, hash_secret

    issued = _issue(owner, s.user(owner, prefix=P))
    _env, _key_id, secret_half = KEY_PATTERN.fullmatch(issued.secret).groups()
    used = "SELECT ingest.api_key_used(%s, %s)"
    app = s.app_conn()  # the submit's own shape: the request role, bound to nobody
    try:
        assert app.execute(used, (issued.id, hash_secret(secret_half + "x"))).fetchone()[0] is False
        assert app.execute(used, (issued.id, None)).fetchone()[0] is False
        assert app.execute(used, (issued.id, b"")).fetchone()[0] is False
        assert _last_used(owner, issued.id) is None
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE ingest.api_key SET last_used_at = now() WHERE id = %s",
                        (issued.id,))
        key = IngestService(app).authenticate(issued.secret)
        assert key is not None and key["id"] == issued.id
        assert _last_used(owner, issued.id) is not None
        wrong = issued.secret[:-1] + ("A" if issued.secret[-1] != "A" else "B")
        assert IngestService(app).authenticate(wrong) is None
    finally:
        app.close()


@pytest.mark.parametrize("refusal", ["revoked", "expired", "other_environment",
                                     "outside_the_allowlist"])
def test_a_refused_presentation_of_the_right_secret_stamps_nothing(owner, refusal):
    from noctornal_api.ingest import IngestService

    over = {"ip_allowlist": ["192.0.2.0/24"]} if refusal == "outside_the_allowlist" else {}
    issued = _issue(owner, s.user(owner, prefix=P), **over)
    token = issued.secret
    if refusal == "revoked":
        owner.execute("UPDATE ingest.api_key SET revoked_at = now(), revoked_reason = 'gone' "
                      "WHERE id = %s", (issued.id,))
    elif refusal == "expired":
        owner.execute("UPDATE ingest.api_key SET created_at = now() - interval '2 days', "
                      "expires_at = now() - interval '1 minute' WHERE id = %s", (issued.id,))
    elif refusal == "other_environment":
        token = token.replace("noct_sk_live_", "noct_sk_test_", 1)
    app = s.app_conn()
    try:
        assert IngestService(app).authenticate(token, peer_ip="198.51.100.9") is None
    finally:
        app.close()
    assert _last_used(owner, issued.id) is None


def test_a_key_is_issued_and_revoked_over_http_as_the_request_role(owner, api):
    from noctornal_api.ingest import IngestService

    admin = es.user(owner, "SYS_ADMIN", prefix=P, clearance="RED")
    hdr = es.session(owner, admin)
    made = api.client.post("/api/v1/ingest/keys", headers=hdr,
                           json={"name": f"{P}partner feed", "ttl_days": 30})
    assert made.status_code == 201, made.text
    body = made.json()
    assert owner.execute("SELECT owner_user_id FROM ingest.api_key WHERE id = %s",
                         (body["id"],)).fetchone()[0] == admin
    app = s.app_conn()
    try:
        assert IngestService(app).authenticate(body["secret"]) is not None
    finally:
        app.close()
    gone = api.client.post(f"/api/v1/ingest/keys/{body['id']}/revoke", headers=hdr,
                           json={"reason": "the partner rotated"})
    assert gone.status_code == 200, gone.text
    assert owner.execute("SELECT revoked_at IS NOT NULL FROM ingest.api_key WHERE id = %s",
                         (body["id"],)).fetchone()[0] is True
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE action IN "
                          "('INGEST_KEY_ISSUED', 'INGEST_KEY_REVOKED') AND actor_id = %s",
                   (admin,)) == 2


def test_a_source_is_stopped_and_started_over_http_as_the_request_role(owner, api):
    uid, email = h.user(owner, P, clearance="AMBER", roles=("COLLECTOR",))
    hdr = h.auth(h.session(owner, email))
    source = h.source(owner, P)
    off = api.client.post(f"/api/v1/collection/sources/{source}/deactivate", headers=hdr,
                          json={"reason": "the board went dark"})
    assert off.status_code == 200 and off.json()["is_active"] is False, off.text
    on = api.client.post(f"/api/v1/collection/sources/{source}/activate", headers=hdr,
                         json={"reason": "it came back"})
    assert on.status_code == 200, on.text
    assert owner.execute("SELECT is_active FROM collect.source WHERE id = %s",
                         (source,)).fetchone()[0] is True
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s AND "
                          "action IN ('SOURCE_DEACTIVATED', 'SOURCE_ACTIVATED') "
                          "AND actor_id = %s", (source, uid)) == 2


def test_an_egress_profile_is_made_over_http_as_the_request_role(owner, api):
    admin = es.user(owner, "SYS_ADMIN", prefix=P, clearance="RED")
    made = api.client.post("/api/v1/admin/egress/profiles", headers=es.session(owner, admin),
                           json={"name": f"{P}{os.urandom(3).hex()}", "kind": "RESIDENTIAL",
                                 "ceiling": "AMBER"})
    assert made.status_code == 201, made.text
    assert owner.execute("SELECT count(*) FROM collect.egress_profile WHERE id = %s",
                         (made.json()["id"],)).fetchone()[0] == 1


def test_a_person_sets_their_own_delivery_over_http_as_the_request_role(owner, api):
    uid, email = h.user(owner, P, clearance="AMBER")
    r = api.client.put("/api/v1/notifications/preferences/SMTP",
                       headers=h.auth(h.session(owner, email)),
                       json={"enabled": False, "min_priority": 1})
    assert r.status_code == 200, r.text
    assert owner.execute("SELECT enabled, min_priority FROM notify.preference "
                         "WHERE user_id = %s AND channel = 'SMTP'", (uid,)).fetchone() == (False, 1)
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE action = "
                          "'NOTIFY_CHANNEL_DISABLED' AND actor_id = %s", (uid,)) == 1


def test_the_privileges_replay_after_the_blanket_grant(owner):
    """`scripts/runtime_roles.py ensure` replays 0108's blanket grant, which
    hands every write back, and then this revision's revoke. Run in a
    transaction that is rolled back, on this test database only."""
    spec = importlib.util.spec_from_file_location(
        "runtime_roles_cfg", ROOT / "scripts" / "runtime_roles.py")
    roles = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(roles)
    held = []
    try:
        with owner.transaction():
            roles.grant(owner)
            held = [(table, privilege)
                    for table, privileges in _writes().items()
                    for privilege in privileges
                    if owner.execute("SELECT has_table_privilege(%s, %s, %s)",
                                     (s.APP_ROLE, table, privilege)).fetchone()[0]]
            raise psycopg.Rollback()
    except psycopg.Rollback:
        pass
    assert held == []
