"""The two workers, scripts/sample_screen.py and scripts/sandbox_dispatch.py
(F13 and F14, 2026-09-24).

Both refuse a bad production environment before opening a connection; the
CLI import needs an active account holding sample.screening.manage and both
recorded authorities, and records that the host operator ran it; a pass
exits 1 while matched bytes wait to move or samples are behind; the
dispatch exits 0 with no sandbox configured and 1 when the preflight
refused.

Email prefix `scrw-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

import capev2_stub
from lab_static_fixtures import MemoryStore, make_user
from screening_fixtures import (
    MemoryPreservation,
    assert_scrubbed,
    declare,
    listed,
    payload,
    scrub,
    service,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "scrw-"
ROOT = Path(__file__).resolve().parents[3]


def _script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def authorities(monkeypatch):
    declare(monkeypatch)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.mark.parametrize("name", ["sample_screen", "sandbox_dispatch"])
def test_the_worker_refuses_a_bad_production_environment_before_any_connection(name, monkeypatch):
    import noctornal_api.db as db
    module = _script(name)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.setenv("NOCTORNAL_HASH_SET_AUTHORITY", "replace-me")

    def no(*_a, **_k):
        raise AssertionError("connected before the environment check")

    monkeypatch.setattr(db, "connect", no)
    with pytest.raises(RuntimeError, match="NOCTORNAL_ENV=production"):
        module.main([])


def _list_file(tmp_path, *blobs):
    path = tmp_path / "list.txt"
    path.write_bytes(listed(*blobs))
    return str(path)


def _cli(tmp_path, email, *blobs, **extra):
    args = ["import", "--file", _list_file(tmp_path, *blobs), "--name", "CLI list",
            "--provider", "Test provider", "--authority", "LIC-2026-002",
            "--category", "OTHER_PROHIBITED", "--as", email]
    for key, value in extra.items():
        args += [key, value]
    return _script("sample_screen").main(args)


def test_cli_import_needs_an_active_account_holding_manage_and_both_authorities(conn, tmp_path, monkeypatch, capsys):
    analyst = make_user(conn, PREFIX, roles=("ANALYST",))
    email = conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                         (analyst,)).fetchone()[0]
    assert _cli(tmp_path, email, payload()) == 2
    assert "sample.screening.manage" in capsys.readouterr().out
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    officer_email = conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                                 (officer,)).fetchone()[0]
    monkeypatch.delenv("NOCTORNAL_HASH_SET_AUTHORITY")
    assert _cli(tmp_path, officer_email, payload()) == 2
    assert "NOCTORNAL_HASH_SET_AUTHORITY" in capsys.readouterr().out
    declare(monkeypatch)
    conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s", (officer,))
    assert _cli(tmp_path, officer_email, payload()) == 2


def test_cli_import_records_the_command_line_and_the_host_user(conn, tmp_path):
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    email = conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                         (officer,)).fetchone()[0]
    assert _cli(tmp_path, email, payload("cli")) == 0
    via = conn.execute("""SELECT imported_via, imported_by FROM lab.screening_list
                           WHERE imported_by = %s""", (officer,)).fetchone()
    assert via == ("cli", officer)
    detail = conn.execute(
        """SELECT detail FROM audit.event WHERE action = 'SCREENING_LIST_IMPORTED'
             AND actor_id = %s ORDER BY seq DESC LIMIT 1""", (officer,)).fetchone()[0]
    assert detail["via"] == "cli" and detail["step_up"] == "not applicable"
    assert "host_user" in detail and detail["account_asserted"] is True


def test_the_pass_exits_one_while_bytes_await_preservation(conn, tmp_path, monkeypatch, capsys):
    import noctornal_api.samples as samples
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    who = make_user(conn, PREFIX, roles=("ANALYST",))
    store = MemoryStore()
    blob = payload("worker")
    service(conn, store).submit(blob, submitted_by=who)
    from screening_fixtures import import_list
    import_list(conn, officer, listed(blob), samples=service(conn, store))
    refusing = MemoryPreservation(fail=True)
    monkeypatch.setattr(samples, "SampleStorage", lambda: store)
    monkeypatch.setattr(samples, "PreservationStorage", lambda: refusing)
    module = _script("sample_screen")
    assert module.main([]) == 1
    assert "pending=" in capsys.readouterr().out
    working = MemoryPreservation()
    monkeypatch.setattr(samples, "PreservationStorage", lambda: working)
    code = module.main([])
    out = capsys.readouterr().out
    assert "preserved=1" in out
    assert code in (0, 1)   # 1 only if the demo estate holds unscreened rows
    assert module.main(["status"]) == 0


def test_the_dispatch_exits_zero_with_no_sandbox_and_one_when_the_preflight_refuses(conn, tmp_path, monkeypatch, capsys):
    from noctornal_api import sandbox
    for var in sandbox.ALL_ENV:
        monkeypatch.delenv(var, raising=False)
    module = _script("sandbox_dispatch")
    assert module.main([]) == 0
    assert "no sandbox is configured" in capsys.readouterr().out
    stub, port, ca, server = capev2_stub.start(tmp_path)
    try:
        capev2_stub.configure(monkeypatch, port, ca)
        stub.web_open = True
        import noctornal_api.samples as samples
        store = MemoryStore()
        monkeypatch.setattr(samples, "SampleStorage", lambda: store)
        role = "SCRWTEST_DETONATOR"
        conn.execute("INSERT INTO iam.role (key, display_name) VALUES (%s, 't') "
                     "ON CONFLICT DO NOTHING", (role,))
        conn.execute("INSERT INTO iam.role_permission VALUES (%s, 'sample.detonate') "
                     "ON CONFLICT DO NOTHING", (role,))
        try:
            who = make_user(conn, PREFIX, roles=(role,))
            s = service(conn, store).submit(payload("d"), submitted_by=who)
            sandbox.SandboxService(conn, service(conn, store)).request(
                s.id, requested_by=who)
            assert module.main([]) == 1
            assert "preflight open_sandbox" in capsys.readouterr().out
        finally:
            conn.execute("DELETE FROM iam.user_role WHERE role_key = %s", (role,))
            conn.execute("DELETE FROM iam.role_permission WHERE role_key = %s", (role,))
            conn.execute("DELETE FROM iam.role WHERE key = %s", (role,))
    finally:
        server.shutdown()
        server.server_close()
