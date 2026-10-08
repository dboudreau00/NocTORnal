"""The request role reads no sealed column outside the accounts table (0180).

A persona's sealed credential and forum session, an ingest key's HMAC, a
lookup provider's sealed key, a download ticket's hash and a sample's
sealed data key are refused to the request role, bound or not. What read
them now reads a generated column (whether a credential is held, whether a
key was destroyed) or a definer: a provider's key for the system role
alone, the two ticket spends and a refused ticket's read by the hash its
holder presents, and a sample's key for whoever may handle its bytes. Run
as the request role, and over HTTP in production's shape
(NOCTORNAL_TEST_ASSUME_ROLE). Account prefix `rlsseal-`.
"""
from __future__ import annotations

import importlib.util
import io
import re
import zipfile
from pathlib import Path

import psycopg
import pytest

import collection_helpers as h
import outbound_support as ob
import rls_support as s
from lab_static_fixtures import MemoryStore
from screening_fixtures import declare, payload, scrub

pytestmark = s.GATED

P = "rlsseal-"
ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"
APP = "https://app.example"
SAMPLES = "https://samples.example"


def _migration():
    path = next(VERSIONS.glob("0180_*.py"))
    spec = importlib.util.spec_from_file_location("m0180", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    declare(monkeypatch)
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    c.execute(f"DELETE FROM lab.download_ticket WHERE user_id IN {users}")
    h.teardown(c, P)
    ob.teardown(c, P)
    s.cleanup(c, P)
    scrub(c, P)
    c.close()


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


def _bound(owner, uid):
    _sid, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _worker():
    from noctornal_api.db import connect
    c = connect()
    c.execute(f"SET ROLE {s.WORKER_ROLE}")
    return c


def _lab_user(owner, clearance="AMBER"):
    uid = s.user(owner, clearance, prefix=P)
    s.grant_global(owner, uid, "MALWARE_ANALYST")
    return uid


def _sample(owner, store, by, **kw):
    from noctornal_api.samples import SampleService
    return SampleService(owner, store).submit(payload("seal"), submitted_by=by, **kw)


def _ticket(owner, user, *, sample=None, evidence=None, purpose="download",
            expired=False):
    """(raw ticket, row id), written as the mint writes it."""
    from noctornal_api.samples import new_download_ticket
    from noctornal_api.security.tokens import hash_token
    raw = new_download_ticket()
    when = ("now() - interval '2 minutes', now() - interval '1 minute'" if expired
            else "now(), now() + interval '30 seconds'")
    row = owner.execute(
        f"""INSERT INTO lab.download_ticket
                (token_hash, sample_id, evidence_id, user_id, issued_at, expires_at,
                 purpose)
            VALUES (%s, %s, %s, %s, {when}, %s) RETURNING id""",
        (hash_token(raw), sample, evidence, user, purpose)).fetchone()[0]
    return raw, row


@pytest.mark.parametrize("bound", [False, True], ids=["unbound", "bound"])
def test_no_sealed_column_is_readable_to_the_request_role(owner, bound):
    m = _migration()
    uid = _lab_user(owner, "RED")
    s.grant_global(owner, uid, "SYS_ADMIN")
    _sid, raw = s.session(owner, uid)
    app = s.app_conn(raw if bound else None)
    try:
        for table, columns in m.SEALED.items():
            for column in columns:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    app.execute(f"SELECT {column} FROM {table} LIMIT 1")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(f"SELECT * FROM {table} LIMIT 1")
            # What the request path reads by name is untouched.
            app.execute(f"SELECT count(id) FROM {table}").fetchone()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE lab.download_ticket SET redeemed_at = now() WHERE false")
    finally:
        app.close()


def test_the_generated_columns_say_what_the_sealed_ones_hold(owner, store):
    for table, generated, sealed in (
            ("collect.collection_account", "secret_stored",
             "coalesce(octet_length(secret_ciphertext), 0) > 0"),
            ("lab.sample", "data_key_destroyed", "octet_length(data_key_ciphertext) = 0")):
        assert owner.execute(f"SELECT count(*) FROM {table} "
                             f"WHERE {generated} IS DISTINCT FROM ({sealed})").fetchone()[0] == 0
    persona = h.persona(owner, P, platform=None)
    sample = _sample(owner, store, _lab_user(owner))
    app = s.app_conn()
    try:
        ask = "SELECT secret_stored FROM collect.collection_account WHERE id = %s"
        assert app.execute(ask, (persona,)).fetchone()[0] is False
        owner.execute("UPDATE collect.collection_account SET secret_ciphertext = '\\x01', "
                      "secret_key_id = 'k' WHERE id = %s", (persona,))
        assert app.execute(ask, (persona,)).fetchone()[0] is True
        owner.execute("UPDATE collect.collection_account SET secret_ciphertext = ''::bytea, "
                      "secret_key_id = NULL WHERE id = %s", (persona,))
        assert app.execute(ask, (persona,)).fetchone()[0] is False
    finally:
        app.close()
    assert sample.key_destroyed is False


def test_a_provider_key_is_the_system_roles_alone(owner):
    from noctornal_api import providers
    a, _ae = ob.make_user(owner, P, clearance="RED", global_roles=("SYS_ADMIN",))
    b, _be = ob.make_user(owner, P, clearance="RED", global_roles=("SYS_ADMIN",))
    made, _route_for = ob.make_provider(owner, a, b, enable=False)
    sealed = bytes(owner.execute("SELECT secret_ciphertext FROM ingest.provider "
                                 "WHERE id = %s", (made.id,)).fetchone()[0])
    ask = "SELECT ingest.provider_secret(%s)"
    for app in (s.app_conn(), _bound(owner, a)):
        try:
            assert app.execute(ask, (made.id,)).fetchone()[0] is None
            seen = providers.get_provider(app, made.id)
            assert seen.secret_ciphertext is None and seen.secret_held is True
        finally:
            app.close()
    worker = _worker()
    try:
        assert bytes(worker.execute(ask, (made.id,)).fetchone()[0]) == sealed
        assert providers.get_provider(worker, made.id).secret_ciphertext == sealed
    finally:
        worker.close()


def test_a_ticket_is_spent_and_explained_only_by_the_hash_its_holder_presents(owner, store):
    from noctornal_api.security.tokens import hash_token
    holder = _lab_user(owner)
    sample, other = _sample(owner, store, holder), _sample(owner, store, holder)
    raw, ticket = _ticket(owner, holder, sample=sample.id)
    stale, _old = _ticket(owner, holder, sample=sample.id, expired=True)
    spend = ("SELECT id, user_id, purpose FROM lab.spend_sample_ticket(%s, %s)")
    why = ("SELECT user_id, sample_id, redeemed_at IS NOT NULL, expired "
           "FROM lab.ticket_by_hash(%s)")
    app = s.app_conn()  # the sample origin's own shape: bound to nobody
    try:
        # Presented on another sample's path: matched nothing and NOT spent.
        assert app.execute(spend, (hash_token(raw), other.id)).fetchall() == []
        assert app.execute(why, (hash_token(raw),)).fetchone() == (
            holder, sample.id, False, False)
        assert app.execute(spend, (hash_token(raw), sample.id)).fetchall() == [
            (ticket, holder, "download")]
        assert app.execute(spend, (hash_token(raw), sample.id)).fetchall() == []
        assert app.execute(why, (hash_token(raw),)).fetchone()[2] is True
        assert app.execute(spend, (hash_token(stale), sample.id)).fetchall() == []
        assert app.execute(why, (hash_token(stale),)).fetchone()[3] is True
        assert app.execute(why, (hash_token(raw + "x"),)).fetchone() is None
    finally:
        app.close()


def test_a_production_ticket_is_spent_only_on_its_own_exhibit_and_case(owner):
    from noctornal_api.security.tokens import hash_token
    lead = s.user(owner, "AMBER", prefix=P)
    case_id, elsewhere = s.case(owner, lead), s.case(owner, lead)
    exhibit = s.exhibit(owner, case_id, lead)
    raw, ticket = _ticket(owner, lead, evidence=exhibit, purpose="exhibit_production")
    spend = "SELECT id FROM lab.spend_production_ticket(%s, %s, 'exhibit_production', %s)"
    app = s.app_conn()
    try:
        assert app.execute(spend, (hash_token(raw), exhibit, elsewhere)).fetchall() == []
        assert app.execute(spend, (hash_token(raw), exhibit, case_id)).fetchall() == [(ticket,)]
        assert app.execute(
            "SELECT evidence_id, evidence_case FROM lab.ticket_by_hash(%s)",
            (hash_token(raw),)).fetchone() == (exhibit, case_id)
    finally:
        app.close()


def test_a_sample_key_is_answered_only_to_who_may_handle_the_bytes(owner, store):
    from noctornal_api.db import bind_ticket
    from noctornal_api.security.tokens import hash_token
    analyst = _lab_user(owner)                      # sample.download and sample.analyse
    reader = s.user(owner, "AMBER", prefix=P)       # no Lab verb
    sample = _sample(owner, store, analyst)
    above = _sample(owner, store, analyst, classification="RED")
    sealed = bytes(owner.execute("SELECT data_key_ciphertext FROM lab.sample WHERE id = %s",
                                 (sample.id,)).fetchone()[0])
    key = "SELECT data_key_ciphertext FROM lab.sample_data_key(%s)"

    def answered(conn, sample_id):
        row = conn.execute(key, (sample_id,)).fetchone()
        return None if row is None else bytes(row[0])

    for who, sample_id, expected in ((analyst, sample.id, sealed), (analyst, above.id, None),
                                     (reader, sample.id, None)):
        app = _bound(owner, who)
        try:
            assert answered(app, sample_id) == expected, (who, sample_id)
        finally:
            app.close()
    unspent, _t1 = _ticket(owner, analyst, sample=sample.id)
    raw, _t2 = _ticket(owner, analyst, sample=sample.id)
    app = s.app_conn()
    try:
        assert answered(app, sample.id) is None
        bind_ticket(app, unspent)
        assert answered(app, sample.id) is None, "a ticket nobody spent binds nothing"
        assert app.execute("SELECT count(*) FROM lab.spend_sample_ticket(%s, %s)",
                           (hash_token(raw), sample.id)).fetchone()[0] == 1
        bind_ticket(app, raw)
        assert answered(app, sample.id) == sealed
        assert answered(app, above.id) is None, "the ticket names one sample"
        owner.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s", (analyst,))
        assert answered(app, sample.id) is None, "a holder no longer active opens nothing"
    finally:
        app.close()
    worker = _worker()
    try:
        assert answered(worker, above.id) is not None
    finally:
        worker.close()


def test_a_download_is_minted_and_served_as_the_request_role(owner, store, monkeypatch):
    """The whole hand-off in production's shape: minted on the application
    origin, spent at the sample origin by a connection bound to nobody, the
    key read through the ticket the redemption just spent."""
    for var in ("NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_PUBLIC_ORIGIN", "NOCTORNAL_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    analyst = _lab_user(owner, "RED")
    sample = _sample(owner, store, analyst)
    _sid, raw = s.session(owner, analyst)
    client, _app = h.client()
    minted = client.post(f"/api/v1/samples/{sample.id}/download-ticket",
                         headers={"Authorization": f"Bearer {raw}"})
    assert minted.status_code in (200, 201), minted.text
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    served = client.post(f"/api/v1/samples/{sample.id}/download",
                         data={"ticket": minted.json()["ticket"]})
    assert served.status_code == 200, served.text
    assert zipfile.is_zipfile(io.BytesIO(served.content))
    assert owner.execute("SELECT count(*) FROM lab.sample_access WHERE sample_id = %s "
                         "AND action = 'DOWNLOADED' AND actor_id = %s",
                         (sample.id, analyst)).fetchone()[0] == 1


def test_execute_on_the_definers_is_the_runtime_roles_and_not_public(owner):
    for fn in _migration().FUNCTIONS:
        acl = owner.execute("SELECT coalesce(proacl::text, '') FROM pg_proc "
                            "WHERE oid = %s::regprocedure", (fn,)).fetchone()[0]
        assert not re.search(r"(^|[{,])=X/", acl), fn
        for role in (s.APP_ROLE, s.WORKER_ROLE):
            assert owner.execute("SELECT has_function_privilege(%s, %s, 'EXECUTE')",
                                 (role, fn)).fetchone()[0] is True, (fn, role)


def test_the_privileges_replay_after_the_blanket_grant(owner):
    """`scripts/runtime_roles.py ensure` replays 0108's blanket grant, which
    hands table SELECT and 0109's UPDATE of `redeemed_at` back, and then
    this revision's revoke. Run in a transaction that is rolled back."""
    spec = importlib.util.spec_from_file_location(
        "runtime_roles_seal", ROOT / "scripts" / "runtime_roles.py")
    roles = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(roles)
    m = _migration()
    seen: dict = {}
    try:
        with owner.transaction():
            roles.grant(owner)
            for table, columns in m.SEALED.items():
                seen[table] = (
                    owner.execute("SELECT has_table_privilege(%s, %s, 'SELECT')",
                                  (s.APP_ROLE, table)).fetchone()[0],
                    [c for c in columns if owner.execute(
                        "SELECT has_column_privilege(%s, %s, %s, 'SELECT')",
                        (s.APP_ROLE, table, c)).fetchone()[0]],
                    owner.execute("SELECT has_column_privilege(%s, %s, 'id', 'SELECT')",
                                  (s.APP_ROLE, table)).fetchone()[0])
            seen["redeem"] = owner.execute(
                "SELECT has_column_privilege(%s, 'lab.download_ticket', 'redeemed_at', "
                "'UPDATE')", (s.APP_ROLE,)).fetchone()[0]
            raise psycopg.Rollback()
    except psycopg.Rollback:
        pass
    assert seen.pop("redeem") is False
    assert seen == {table: (False, [], True) for table in m.SEALED}, seen
