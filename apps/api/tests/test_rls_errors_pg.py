"""What a row-security refusal and a missing system connection answer (S1,
2026-09-25).

A WITH CHECK refusal means the gate let through a write
the policy refuses: the second line firing, which is a finding, so it is a
403 with an RLS_REFUSED audit row written out of band. A 42501 that is a
missing GRANT is a deployment defect and stays the 500 it always was. No
system connection is a 503 that names the setting.
"""
from __future__ import annotations

import psycopg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import rls_support as s

pytestmark = s.GATED


def _app(exc: BaseException) -> TestClient:
    from noctornal_api.http.errors import install_error_handlers
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    def boom():
        raise exc

    return TestClient(app, raise_server_exceptions=False)


def _real_refusal() -> psycopg.errors.InsufficientPrivilege:
    """The server's own refusal, as the request role, bound to nobody."""
    owner = s.owner_conn()
    app = s.app_conn()
    try:
        case_id = owner.execute('SELECT id FROM core."case" LIMIT 1').fetchone()[0]
        user_id = owner.execute("SELECT id FROM iam.app_user LIMIT 1").fetchone()[0]
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as info:
            app.execute("INSERT INTO core.node (case_id, node_type, label, created_by) "
                        "VALUES (%s, 'IDENTITY', 'refused', %s)", (case_id, user_id))
        return info.value
    finally:
        app.close()
        owner.close()


def test_a_real_row_security_refusal_is_recognised():
    from noctornal_api.http.errors import is_rls_refusal
    assert is_rls_refusal(_real_refusal())


def test_a_refusal_is_a_403_and_an_audit_row():
    exc = _real_refusal()
    response = _app(exc).get("/boom")
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail.startswith("The database refused this change")
    ref = detail.rsplit("(ref ", 1)[1].rstrip(")")
    owner = s.owner_conn()
    try:
        row = owner.execute(
            """SELECT outcome, detail->>'path' FROM audit.event
                WHERE action = 'RLS_REFUSED' AND detail->>'ref' = %s""",
            (ref,)).fetchone()
    finally:
        owner.close()
    assert row == ("DENIED", "/boom")


def test_a_missing_grant_stays_a_500_and_is_not_called_a_row_refusal():
    from noctornal_api.http.errors import is_rls_refusal
    exc = psycopg.errors.InsufficientPrivilege("permission denied for table node")
    assert not is_rls_refusal(exc)
    assert _app(exc).get("/boom").status_code == 500
    # The right words about a table that is not under policy are not one.
    other = psycopg.errors.InsufficientPrivilege(
        'new row violates row-level security policy for table "retention_rule"')
    assert not is_rls_refusal(other)


def test_no_system_connection_is_a_503_that_names_the_setting():
    from noctornal_api.db import SystemContextUnavailable
    response = _app(SystemContextUnavailable("no worker")).get("/boom")
    assert response.status_code == 503
    assert "NOCTORNAL_WORKER_DATABASE_URL" in response.json()["detail"]


def test_a_system_connection_is_refused_when_it_would_be_filtered(monkeypatch):
    """connect_system never hands back a row-filtered connection: pointed
    at the request role it refuses, rather than letting a purge see part
    of the data."""
    from noctornal_api import db
    monkeypatch.setattr(db, "WORKER_ROLE", s.APP_ROLE)
    monkeypatch.setenv(db.ASSUME_ROLE_ENV, "1")
    with pytest.raises(db.SystemContextUnavailable, match="subject to row-level security"):
        db.connect_system(db.SystemPurpose.READINESS)
