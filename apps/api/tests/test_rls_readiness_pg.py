"""The readiness row for row-level security (S1, 2026-09-25).

Red on the owner's connection (every development database and the main
suite, for app_db_role_not_owner's reason), green only when all four facts
hold: the registry's tables are under policy, this connection is filtered,
the IAM plane is read-only to it, and a system connection opens that owns
nothing. A database with no policies at all is red, not vacuously green.
"""
from __future__ import annotations

import rls_support as s

pytestmark = s.GATED

NAME = "row_level_security_enforced"


def _check(conn):
    from noctornal_api import readiness
    probe = dict((name, fn) for name, fn, _ in readiness._CHECKS)[NAME]
    return probe(conn)


def test_the_row_is_registered_and_not_blocking():
    from noctornal_api import readiness
    assert NAME in readiness.CHECK_NAMES
    assert NAME not in readiness.CONSEQUENCES


def test_the_owner_connection_is_red_and_says_why():
    conn = s.owner_conn()
    try:
        check = _check(conn)
    finally:
        conn.close()
    assert check.ok is False
    assert "row-level security does not filter" in check.evidence
    assert "noctornal_worker" in check.action


def test_the_request_role_with_a_system_role_is_green(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    owner = s.owner_conn()
    uid = s.user(owner, "AMBER")
    _, raw = s.session(owner, uid)
    app = s.app_conn(raw)
    try:
        check = _check(app)
    finally:
        app.close()
        s.cleanup(owner)
        owner.close()
    assert check.ok is True, check.evidence
    assert s.APP_ROLE in check.evidence and s.WORKER_ROLE in check.evidence


def test_a_registry_table_without_row_security_turns_it_red(monkeypatch):
    """Vacuity guard: the row names what is missing rather than passing on
    an empty policy set."""
    from noctornal_api import rls_registry
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    monkeypatch.setitem(rls_registry.POLICY, "core.retention_rule", "ELEMENT")
    owner = s.owner_conn()
    uid = s.user(owner, "AMBER")
    _, raw = s.session(owner, uid)
    app = s.app_conn(raw)
    try:
        check = _check(app)
    finally:
        app.close()
        s.cleanup(owner)
        owner.close()
    assert check.ok is False
    assert "core.retention_rule" in check.evidence
