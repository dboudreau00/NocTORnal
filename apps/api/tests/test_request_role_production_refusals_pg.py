"""A production request connection is refused when its role is a superuser,
bypasses row security or is the schema owner (infra-4, 2026-10-03).

`config.verify_environment` refuses the names it can see in the DSN (see
`test_g48_request_role_boot.py`); this is the half that reads the catalog,
once per process and DSN, for a role under another name or one that merely
holds the owner's membership. As in the row-security suites the runtime roles
are reached by SET ROLE from the owner's own login, so no password enters the
test environment. Env-gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE.
"""
from __future__ import annotations

import pytest
from rls_support import APP_ROLE, GATED, WORKER_ROLE

from noctornal_api import db

pytestmark = GATED


@pytest.fixture(autouse=True)
def _nothing_proven_yet(monkeypatch):
    monkeypatch.setattr(db, "_REQUEST_ROLE_PROVEN", set())


@pytest.fixture
def owner():
    conn = db.connect()
    yield conn
    conn.close()


def _as(conn, role: str):
    conn.execute(f"SET ROLE {role}")
    return conn


def test_the_owner_is_refused_in_production(owner, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    with pytest.raises(db.SystemContextUnavailable) as refused:
        db.refuse_privileged_request_role(owner)
    assert "DATABASE_URL must name noctornal_app" in str(refused.value)
    assert db._REQUEST_ROLE_PROVEN == set(), "a refusal proves nothing"


def test_a_role_that_bypasses_row_security_is_refused_whatever_its_name(owner, monkeypatch):
    """The system role is BYPASSRLS and owns nothing: not the owner, not a
    superuser, and exactly the role the request connection must not be."""
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    with pytest.raises(db.SystemContextUnavailable):
        db.refuse_privileged_request_role(_as(owner, WORKER_ROLE))


def test_the_request_role_is_accepted_and_remembered(owner, monkeypatch):
    """The other direction: what a legitimate production deployment connects
    as is untouched, and is asked once per process and DSN."""
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    db.refuse_privileged_request_role(_as(owner, APP_ROLE))
    assert len(db._REQUEST_ROLE_PROVEN) == 1
    # Proven is proven for the DSN: not asked again, so even the owner's
    # connection under it (which cannot happen) passes unasked.
    owner.execute("RESET ROLE")
    db.refuse_privileged_request_role(owner)


def test_development_and_the_suite_connect_as_the_owner_unasked(owner, monkeypatch):
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    db.refuse_privileged_request_role(owner)
    assert db._REQUEST_ROLE_PROVEN == set()


def test_connect_request_in_production_refuses_the_owner(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(db.ASSUME_ROLE_ENV, raising=False)
    with pytest.raises(db.SystemContextUnavailable):
        db.connect_request()


def test_connect_request_in_production_serves_the_request_role(monkeypatch):
    """The same call with the role the deployment names: a usable connection,
    as the role the register's `app_db_role_not_owner` row asks for."""
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.setenv(db.ASSUME_ROLE_ENV, "1")
    conn = db.connect_request()
    try:
        assert conn.execute("SELECT current_user").fetchone()[0] == APP_ROLE
    finally:
        conn.close()
