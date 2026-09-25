"""scripts/egress_setup.py, the headless egress configuration (S2, 2026-09-24).

Every write signs its operator in: a claimed email is not an identity. The
prompts are injected; the database is the real one (DATABASE_URL) for the
commands that write.
"""
from __future__ import annotations

import importlib.util
import io
import os
import time
from pathlib import Path
from uuid import uuid4

import pytest

import egress_support as es
from noctornal_api import egress_ledger
from noctornal_api.security import egress_seal

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "egress_setup.py"
DATABASE_URL = os.environ.get("DATABASE_URL", "")
needs_db = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
PREFIX = "egs-"
PASSWORD = "correct horse battery 42"


def _module():
    spec = importlib.util.spec_from_file_location("egress_setup", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


setup = _module()


def _run(argv, *, answers=(), secrets=(), stdin=None, compose=lambda: (2, 29)):
    out = []
    answers, secrets = list(answers), list(secrets)
    code = setup.run(argv, ask=lambda _p: answers.pop(0), secret=lambda _p: secrets.pop(0),
                     stdin=stdin, out=out.append, compose=compose)
    return code, "\n".join(out)


def test_keygen_prints_a_pair_whose_id_the_ring_derives_and_two_more_keys():
    code, text = _run(["keygen"])
    assert code == 0
    values = dict(line.split("=", 1) for line in text.splitlines()
                  if line and not line.startswith("#"))
    ring = egress_seal.ExitRing.from_env(values)
    assert ring.active_id in text
    public = egress_seal.load_public(values["NOCTORNAL_EGRESS_SEAL_PUBLIC"])
    assert egress_seal.key_id(public) == ring.active_id
    assert len(egress_seal.fingerprint_key(values)) == 32


def test_role_sql_prints_the_migrations_grants_verbatim():
    code, text = _run(["role-sql"])
    assert code == 0 and egress_ledger.EGRESS_ROLE_SQL in text
    assert "\\password noctornal_egress" in text and "PASSWORD '" not in text


def test_dev_env_prints_the_host_proxy_lines():
    _code, text = _run(["dev-env"])
    assert "NOCTORNAL_EGRESS_LISTEN=127.0.0.1:3128" in text
    assert "NOCTORNAL_EGRESS_PROXY_URL=http://127.0.0.1:3128" in text


def test_an_endpoint_on_the_command_line_is_refused():
    for flag in ("--host=gw.example", "--password", "--endpoint={}"):
        with pytest.raises(setup.SetupError, match="standard input"):
            setup.run(["profile-exit", "--profile", str(uuid4()), "--exit-kind", "SOCKS5",
                       flag], ask=input, secret=input)


def test_dev_smtp_is_refused_in_production(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    with pytest.raises(setup.SetupError, match="for development"):
        setup.run(["dev-smtp"])


def _write_env_files(directory: Path, override=None):
    keys = es.keys()
    files = {
        "egress-client.env": {k: keys[k] for k in ("NOCTORNAL_EGRESS_CLIENT_KEY",
                                                   "NOCTORNAL_EGRESS_FINGERPRINT_KEY",
                                                   "NOCTORNAL_EGRESS_SEAL_PUBLIC")},
        "egress-proxy.env": {
            "NOCTORNAL_EGRESS_DATABASE_URL": "postgresql://noctornal_egress:pw-1@postgres/noctornal",
            **{k: keys[k] for k in ("NOCTORNAL_EGRESS_CLIENT_KEY", "NOCTORNAL_EGRESS_SEAL_KEY",
                                    "NOCTORNAL_EGRESS_FINGERPRINT_KEY")}},
        "postgres-init.env": {"NOCTORNAL_EGRESS_DB_PASSWORD": "pw-1"},
    }
    for (name, key), value in (override or {}).items():
        if value is None:
            files[name].pop(key, None)
        else:
            files[name][key] = value
    for name, values in files.items():
        (directory / name).write_text(
            "".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")


def test_preflight_passes_on_good_files(tmp_path):
    _write_env_files(tmp_path)
    assert setup.preflight(tmp_path, compose=lambda: (2, 29)) == []


def test_preflight_names_a_missing_file_a_malformed_key_and_a_mismatch(tmp_path):
    _write_env_files(tmp_path, {("egress-client.env", "NOCTORNAL_EGRESS_FINGERPRINT_KEY"):
                                "not-base64!!"})
    (tmp_path / "postgres-init.env").unlink()
    problems = setup.preflight(tmp_path, compose=lambda: (2, 29))
    assert "postgres-init.env is missing (copy postgres-init.env.example and fill it in)." \
        in problems
    assert any("egress-client.env: NOCTORNAL_EGRESS_FINGERPRINT_KEY is not a well formed key"
               in p for p in problems)
    assert any("differs between egress-client.env and egress-proxy.env" in p for p in problems)
    assert all("not-base64" not in p for p in problems)


def test_preflight_checks_the_compose_floor(tmp_path):
    _write_env_files(tmp_path)
    assert any("older than 2.24" in p for p in setup.preflight(tmp_path, compose=lambda: (2, 20)))
    assert any("could not be read" in p for p in setup.preflight(tmp_path, compose=lambda: None))


def test_preflight_notices_a_public_key_from_another_pair(tmp_path):
    _write_env_files(tmp_path, {("egress-client.env", "NOCTORNAL_EGRESS_SEAL_PUBLIC"):
                                es.old_seal_public()})
    assert any("is not the public half" in p
               for p in setup.preflight(tmp_path, compose=lambda: (2, 29)))


# ---------------------------------------------------------------------------
# Signing in
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.preserved(c):
        yield c
        # The routes this suite's operators made go, retired or not.
        made = f"""(SELECT id FROM collect.egress_integration_route WHERE created_by IN
                    (SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%%'))"""
        c.execute(f"DELETE FROM collect.egress_destination WHERE route_id IN {made}")
        c.execute(f"DELETE FROM collect.egress_integration_route WHERE id IN {made}")
        es.teardown(c, PREFIX)
    c.close()


def _operator(conn, *roles, must_change=False):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    store = PgUserStore(conn)
    email = f"{PREFIX}{uuid4().hex[:8]}@noctornal.test"
    uid = store.create_user(email, "Operator", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET must_change_password = %s WHERE id = %s",
                 (must_change, uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    code = totp.code_at(secret, int(time.time()))
    return uid, email, code, store


def _audit(conn, action, since_seq):
    return conn.execute("SELECT actor_id, detail FROM audit.event WHERE action = %s AND seq > %s "
                        "ORDER BY seq", (action, since_seq)).fetchall()


def _seq(conn):
    return conn.execute("SELECT max(seq) FROM audit.event").fetchone()[0]


@needs_db
def test_a_claimed_email_without_credentials_is_refused_and_writes_nothing(conn):
    uid, email, _code, _store = _operator(conn, "SYS_ADMIN")
    before = _seq(conn)
    with pytest.raises(setup.SetupError, match="Sign-in failed"):
        _run(["route-create", "--name", "smtp", "--description", "a relay route"],
             answers=[email], secrets=["wrong password", "000000"])
    failed = _audit(conn, "AUTH_FAILED", before)
    assert len(failed) == 1 and failed[0][1]["via"] == "scripts/egress_setup.py"
    assert not _audit(conn, "EGRESS_ROUTE_CREATED", before)


@needs_db
def test_the_script_records_the_signed_in_operator(conn):
    uid, email, code, _store = _operator(conn, "SYS_ADMIN")
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = %s, retire_reason = 'setup suite'
                    WHERE name = 'smtp' AND retired_at IS NULL""", (uid,))
    before = _seq(conn)
    rc, text = _run(["dev-smtp"], answers=[email], secrets=[PASSWORD, code])
    assert rc == 0 and "EGRESS_ROUTE_CREATED smtp" in text
    rows = _audit(conn, "EGRESS_ROUTE_CREATED", before)
    assert len(rows) == 1 and rows[0][0] == uid
    detail = rows[0][1]
    assert detail["via"] == "scripts/egress_setup.py" and detail["host"] and detail["os_user"]
    assert conn.execute("SELECT entry FROM collect.egress_destination d JOIN "
                        "collect.egress_integration_route r ON r.id = d.route_id "
                        "WHERE r.name = 'smtp' AND r.retired_at IS NULL AND d.retired_at "
                        "IS NULL").fetchone()[0] == "localhost:1025"


@needs_db
def test_an_issued_password_never_changed_is_refused(conn):
    _uid, email, code, _store = _operator(conn, "SYS_ADMIN", must_change=True)
    with pytest.raises(setup.SetupError, match="replace the issued password"):
        _run(["dev-smtp"], answers=[email], secrets=[PASSWORD, code])


@needs_db
def test_a_recovery_code_is_not_accepted_as_the_second_factor(conn):
    uid, email, _code, store = _operator(conn, "SYS_ADMIN")
    recovery = store.issue_recovery_codes(uid)[0]
    before = _seq(conn)
    with pytest.raises(setup.SetupError, match="recovery code is not accepted"):
        _run(["dev-smtp"], answers=[email], secrets=[PASSWORD, recovery])
    assert _audit(conn, "AUTH_FAILED", before)[0][1]["reason"] == "recovery_code_refused"
    # Refused, and left unspent.
    assert len(store.get_recovery_hashes(uid)) == 10


@needs_db
def test_the_operator_must_hold_egress_manage(conn):
    _uid, email, code, _store = _operator(conn, "SECURITY_OFFICER")
    with pytest.raises(setup.SetupError, match="does not hold egress.manage"):
        _run(["dev-smtp"], answers=[email], secrets=[PASSWORD, code])


@needs_db
def test_profile_exit_reads_its_endpoint_from_standard_input(conn, monkeypatch):
    for key, value in es.keys().items():
        monkeypatch.setenv(key, value)
    uid, email, code, _store = _operator(conn, "SYS_ADMIN")
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    stdin = io.StringIO('{"host": "gw.provider.example", "port": 8443, '
                        '"username": "u-gb", "password": "pw-never-printed"}')
    rc, text = _run(["profile-exit", "--profile", str(pid), "--exit-kind", "HTTPS"],
                    answers=[email], secrets=[PASSWORD, code], stdin=stdin)
    assert rc == 0 and text.startswith("EGRESS_EXIT_SEALED HTTPS egress:")
    assert "pw-never-printed" not in text and "gw.provider.example" not in text
    assert uid
