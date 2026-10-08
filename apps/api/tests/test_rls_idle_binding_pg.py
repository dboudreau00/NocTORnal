"""A connection binds only to a session inside its idle window (0174).

`iam.rls_actor()` checked a session's absolute expiry and not its 30-minute
idle window, so a raw token from a session idle for hours still bound a
request-role connection as its user. The HTTP layer refuses first; this is
the database's own refusal. Accounts carry the prefix `rlsidle-`.
"""
from __future__ import annotations

import importlib.util
from datetime import timedelta
from pathlib import Path

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlsidle-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


def _migration():
    path = next(VERSIONS.glob("0174_*.py"))
    spec = importlib.util.spec_from_file_location("m0174", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c, prefix=PREFIX)
    c.close()


def _aged(owner, sid, minutes: int) -> None:
    owner.execute("UPDATE iam.session SET last_seen_at = now() - make_interval(mins => %s) "
                  "WHERE id = %s", (minutes, sid))


def test_a_session_past_its_idle_window_binds_nobody(owner):
    uid = s.user(owner, prefix=PREFIX)
    case_id = s.case(owner, uid)
    sid, raw = s.session(owner, uid)
    _aged(owner, sid, 31)
    app = s.app_conn(raw)
    try:
        assert app.execute("SELECT iam.rls_actor()").fetchone()[0] is None
        assert s.count(app, 'SELECT count(*) FROM core."case" WHERE id = %s', (case_id,)) == 0
    finally:
        app.close()


def test_a_session_inside_its_idle_window_still_binds(owner):
    uid = s.user(owner, prefix=PREFIX)
    case_id = s.case(owner, uid)
    sid, raw = s.session(owner, uid)
    _aged(owner, sid, 29)
    app = s.app_conn(raw)
    try:
        assert app.execute("SELECT iam.rls_actor()").fetchone()[0] == uid
        assert s.count(app, 'SELECT count(*) FROM core."case" WHERE id = %s', (case_id,)) == 1
    finally:
        app.close()


def test_the_binding_refuses_what_the_http_check_refuses(owner):
    """`deps.refuse_unbindable_session` binds and compares: an idle session
    comes out bound to nobody, which is refused like any bad session."""
    from noctornal_api.db import bind_session
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid)
    _aged(owner, sid, 45)
    app = s.app_conn()
    try:
        binding = bind_session(app, raw)
        assert binding.actor is None and binding.exempt is False
    finally:
        app.close()


def test_the_window_is_the_one_the_sessions_use():
    from noctornal_api.security.sessions import IDLE_TIMEOUT
    m = _migration()
    minutes, unit = m.IDLE_WINDOW.split()
    assert unit == "minutes"
    assert timedelta(minutes=int(minutes)) == IDLE_TIMEOUT
    assert f"interval '{m.IDLE_WINDOW}'" in m.UPGRADE_SQL
    assert "last_seen_at" not in m.DOWNGRADE_SQL
