"""The request role reads no session's token, binding or address, and no
break-glass justification (rls-6, 0177).

Every refusal is paired with the legitimate reader still working: the HTTP
validation (strict binding included) reads a session through
`iam.session_by_token`, `/break-glass/mine` shows the holder their own
justification and the officer's queue shows every one. Run as the request
role bound by a real session's proof, and over HTTP in production's shape.
Account prefix `rlscol-`.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

P = "rlscol-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


def _migration():
    path = next(VERSIONS.glob("0177_*.py"))
    spec = importlib.util.spec_from_file_location("m0177", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c, P)
    c.close()


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    from noctornal_api.db import ASSUME_ROLE_ENV
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("bound", [False, True], ids=["unbound", "bound"])
def test_no_session_column_that_says_who_or_where_is_readable(owner, bound):
    m = _migration()
    uid = s.user(owner, prefix=P)
    _sid, raw = s.session(owner, uid)
    app = s.app_conn(raw if bound else None)
    try:
        for column in m.SESSION_SEALED:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(f"SELECT {column} FROM iam.session LIMIT 1")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM iam.session LIMIT 1")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT count(*) FROM iam.session WHERE token_hash IS NOT NULL")
        # What the request path reads by name is untouched.
        n = app.execute("SELECT count(id), count(user_id), count(last_seen_at), "
                        "count(expires_at) FROM iam.session WHERE user_id = %s",
                        (uid,)).fetchone()
        assert n == (1, 1, 1, 1)
    finally:
        app.close()


def test_the_definer_answers_the_one_session_a_token_names(owner):
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.security.tokens import hash_token
    from noctornal_api.stores import PgSessionStore
    uid = s.user(owner, prefix=P)
    record, raw = SessionService(PgSessionStore(owner)).create(
        uuid4(), uid, mfa_satisfied=True, ip="192.0.2.7", user_agent="rls-col-agent")
    app = s.app_conn()
    try:
        found = PgSessionStore(app).get_by_token_hash(hash_token(raw))
        assert found is not None and found.id == record.id and found.user_id == uid
        assert found.ip == "192.0.2.7" and found.user_agent == "rls-col-agent"
        assert found.token_hash == hash_token(raw)
        assert PgSessionStore(app).get_by_token_hash(hash_token(raw + "x")) is None
    finally:
        app.close()


def test_strict_binding_still_compares_the_minted_client_over_http(owner, client,
                                                                   monkeypatch):
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    monkeypatch.setenv("NOCTORNAL_SESSION_STRICT_BINDING", "1")
    uid = s.user(owner, prefix=P)
    _record, raw = SessionService(PgSessionStore(owner)).create(
        uuid4(), uid, mfa_satisfied=True, user_agent="rls-col-browser")
    good = client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {raw}", "User-Agent": "rls-col-browser"})
    assert good.status_code == 200, good.text
    moved = client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {raw}", "User-Agent": "somebody-else"})
    assert moved.status_code == 401


@pytest.mark.parametrize("bound", [False, True], ids=["unbound", "bound"])
def test_no_break_glass_justification_is_readable(owner, bound):
    analyst = s.user(owner, "AMBER", prefix=P)
    s.break_glass(owner, analyst, "RED")
    _sid, raw = s.session(owner, analyst)
    app = s.app_conn(raw if bound else None)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT justification FROM iam.break_glass")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM iam.break_glass")
        # The gate's own read of a grant is untouched.
        assert s.count(app, "SELECT count(*) FROM iam.break_glass WHERE user_id = %s "
                            "AND granted_classification IS NOT NULL", (analyst,)) == 1
    finally:
        app.close()


def test_the_justification_is_the_holders_and_the_reviewers(owner):
    holder = s.user(owner, "AMBER", prefix=P)
    other = s.user(owner, "AMBER", prefix=P)
    officer = s.user(owner, "AMBER", prefix=P)
    s.grant_global(owner, officer, "SECURITY_OFFICER")
    grant = s.break_glass(owner, holder, "RED")
    ask = "SELECT iam.break_glass_justification(%s)"
    for who, expected in ((holder, True), (officer, True), (other, False)):
        _sid, raw = s.session(owner, who)
        app = s.app_conn(raw)
        try:
            text = app.execute(ask, (grant,)).fetchone()[0]
            assert (text is not None) is expected, who
        finally:
            app.close()
    unbound = s.app_conn()
    try:
        assert unbound.execute(ask, (grant,)).fetchone()[0] is None
    finally:
        unbound.close()
    assert owner.execute(ask, (grant,)).fetchone()[0].startswith("row security test")


def test_the_holder_and_the_officer_still_read_it_over_http(owner, client):
    holder = s.user(owner, "AMBER", prefix=P)
    officer = s.user(owner, "AMBER", prefix=P)
    s.grant_global(owner, officer, "SECURITY_OFFICER")
    grant = s.break_glass(owner, holder, "RED", hours=1)
    _sid, raw = s.session(owner, holder)
    mine = client.get("/api/v1/break-glass/mine",
                      headers={"Authorization": f"Bearer {raw}"})
    assert mine.status_code == 200, mine.text
    assert [g["justification"] for g in mine.json()["grants"] if g["id"] == str(grant)] == [
        "row security test: an emergency of the test kind"]
    owner.execute("UPDATE iam.break_glass SET revoked_at = now() WHERE id = %s", (grant,))
    _sid, raw = s.session(owner, officer)
    queue = client.get("/api/v1/break-glass/unreviewed",
                       headers={"Authorization": f"Bearer {raw}"})
    assert queue.status_code == 200, queue.text
    assert [g["justification"] for g in queue.json()["grants"] if g["id"] == str(grant)] == [
        "row security test: an emergency of the test kind"]


def test_execute_on_the_definers_is_the_runtime_roles_and_not_public(owner):
    for fn in _migration().FUNCTIONS:
        acl = owner.execute("SELECT coalesce(proacl::text, '') FROM pg_proc "
                            "WHERE oid = %s::regprocedure", (fn,)).fetchone()[0]
        assert not re.search(r"(^|[{,])=X/", acl), fn
        for role in (s.APP_ROLE, s.WORKER_ROLE):
            assert owner.execute("SELECT has_function_privilege(%s, %s, 'EXECUTE')",
                                 (role, fn)).fetchone()[0] is True, (fn, role)


def test_the_privileges_replay_cleanly(owner):
    """`scripts/runtime_roles.py ensure` replays PRIVILEGES_SQL after 0108's
    blanket grant; run twice it leaves the same state."""
    m = _migration()
    owner.execute(m.PRIVILEGES_SQL)
    owner.execute(m.PRIVILEGES_SQL)
    for table, sealed in (("iam.session", m.SESSION_SEALED),
                          ("iam.break_glass", m.BREAK_GLASS_SEALED)):
        assert owner.execute("SELECT has_table_privilege(%s, %s, 'SELECT')",
                             (s.APP_ROLE, table)).fetchone()[0] is False
        for column in sealed:
            assert owner.execute("SELECT has_column_privilege(%s, %s, %s, 'SELECT')",
                                 (s.APP_ROLE, table, column)).fetchone()[0] is False
        assert owner.execute("SELECT has_column_privilege(%s, %s, 'id', 'SELECT')",
                             (s.APP_ROLE, table)).fetchone()[0] is True
    # The column UPDATEs 0109 and 0144 left are kept.
    for column in ("last_seen_at", "revoked_at", "revoke_reason"):
        assert owner.execute("SELECT has_column_privilege(%s, 'iam.session', %s, 'UPDATE')",
                             (s.APP_ROLE, column)).fetchone()[0] is True
