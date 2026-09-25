"""scripts/telegram_persona.py: the operator signs in, and enrols, imports
and logs out a Telegram persona's session through the persona gate, with a
fake transport and no network (roadmap F5.2, 2026-09-24).
DATABASE_URL-gated.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

import collection_helpers as h
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-tgscr-"
ROOT = Path(__file__).resolve().parents[3]
PASSWORD = "correct-horse-battery-staple-tg"


def _script():
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "telegram_persona_script", ROOT / "scripts" / "telegram_persona.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    from noctornal_api.http.routers import collection as router

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    monkeypatch.setattr(router, "blocking_failures", lambda _c: [])
    tf.guard_sockets(monkeypatch)
    tf.patch_routes(monkeypatch)
    c = connect()
    yield c
    tp.teardown(c, P)
    h.retire_users(c, P)
    c.close()


class Operator:
    def __init__(self, conn, *, roles=("COLLECTOR",)):
        from uuid import uuid4

        from noctornal_api.security import totp
        from noctornal_api.stores import PgUserStore

        self.conn = conn
        self.email = f"{P}{uuid4().hex[:8]}@noctornal.test"
        store = PgUserStore(conn)
        self.id = store.create_user(self.email, "TG operator", PASSWORD)
        self.totp = totp.generate_secret()
        store.enroll_totp(self.id, self.totp)
        conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                     (self.id,))
        for role in roles:
            conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                         (self.id, role))

    def code(self) -> str:
        from noctornal_api.security import totp

        # One code per 30-second step: the replay counter is reset between
        # sign-ins, which have their own replay tests.
        self.conn.execute("UPDATE iam.app_user SET totp_last_counter = NULL WHERE id = %s",
                          (self.id,))
        return totp.code_at(self.totp, int(time.time()))


def _run(monkeypatch, capsys, op: Operator, argv, *, answers=None, password=None,
         code=None, factory=None, stdin=None):
    """Run main() with the prompts answered. Returns (exit, stdout, stderr)."""
    import builtins
    import getpass

    module = _script()
    module.TRANSPORT_FACTORY = factory
    replies = {"Email": op.email, "Password": password or PASSWORD,
               "Authenticator code": code or op.code(), "api_id": "1234567",
               "Phone number": "+447700900123",
               "api_hash": "0123456789abcdef0123456789abcdef",
               "Login code": "12345", "Two-step password": ""}
    replies.update(answers or {})

    def answer(prompt=""):
        for key, value in replies.items():
            if prompt.startswith(key):
                return value
        raise AssertionError(f"an unexpected prompt: {prompt!r}")

    monkeypatch.setattr(builtins, "input", answer)
    monkeypatch.setattr(getpass, "getpass", answer)
    if stdin is not None:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    done = module.main(argv)
    out = capsys.readouterr()
    return done, out.out, out.err


def _authority(conn, pid):
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                source_ids=[])


def _fresh(conn, *, authority=True):
    pid, _e, _uid = tp.persona(conn, P, enrolled=False)
    if authority:
        _authority(conn, pid)
    return pid


def _fx(uid=None):
    """A fixture signing in as a fresh account each run: accounts are unique
    and platform-bound personas are never deleted."""
    return tp.fixture_for({"peer_type": "CHANNEL", "peer_id": 1, "username": "x"},
                          uid or f"u:{tp.rand_id()}")


def _row(conn, pid):
    return conn.execute(
        """SELECT platform_uid, session_enrolled_at, octet_length(secret_ciphertext),
                  machine_lock_code, machine_hold_reason
             FROM collect.collection_account WHERE id = %s""", (pid,)).fetchone()


# --- the sign-in ---------------------------------------------------------------

def test_the_script_refuses_an_operator_who_does_not_sign_in(conn, monkeypatch, capsys):
    op = Operator(conn)
    pid = _fresh(conn)
    done, out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                          password="not-the-password", factory=tf.FakeFactory(_fx()))
    assert done == 1 and err.strip() == "The sign-in did not verify." and out == ""
    detail = conn.execute(
        """SELECT detail FROM audit.event WHERE action = 'AUTH_FAILED'
              AND detail->>'email' = %s""", (op.email,)).fetchone()[0]
    assert detail["via"] == "scripts/telegram_persona.py"
    assert _row(conn, pid)[2] in (None, 0)


def test_the_script_refuses_an_issued_password_that_was_never_changed(
        conn, monkeypatch, capsys):
    op = Operator(conn)
    conn.execute("UPDATE iam.app_user SET must_change_password = true WHERE id = %s",
                 (op.id,))
    pid = _fresh(conn)
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                           factory=tf.FakeFactory(_fx()))
    assert done == 1 and "replace the issued password first" in err


def test_a_wrong_password_never_reveals_the_accounts_reset_state(conn, monkeypatch, capsys):
    op = Operator(conn)
    conn.execute("UPDATE iam.app_user SET must_change_password = true WHERE id = %s",
                 (op.id,))
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(_fresh(conn))],
                           password="wrong-password")
    assert done == 1 and err.strip() == "The sign-in did not verify."


def test_a_recovery_code_does_not_sign_in_the_script_and_stays_usable(
        conn, monkeypatch, capsys):
    """authenticate(spend_recovery=False) accepts a
    recovery code and leaves it unspent; the script refuses it after the
    fact, twice, and the code still signs in once at the console."""
    from noctornal_api.security.auth import AuthService
    from noctornal_api.stores import PgUserStore

    op = Operator(conn)
    code = PgUserStore(conn).issue_recovery_codes(op.id, 1)[0]
    pid = _fresh(conn)
    for _ in range(2):
        done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                               code=code, factory=tf.FakeFactory(_fx()))
        assert done == 1 and "A recovery code does not sign in this script" in err
    assert conn.execute(
        """SELECT count(*) FROM audit.event WHERE action = 'AUTH_FAILED'
              AND detail->>'reason' = 'recovery_code_refused'
              AND detail->>'email' = %s""", (op.email,)).fetchone()[0] == 2
    assert AuthService(PgUserStore(conn)).authenticate(op.email, PASSWORD, code).ok


def test_the_operator_must_hold_collection_account_manage(conn, monkeypatch, capsys):
    op = Operator(conn, roles=("ANALYST",))
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(_fresh(conn))])
    assert done == 1 and "collection_account.manage" in err


# --- enrol -------------------------------------------------------------------------

def test_enrol_refuses_without_a_confirmed_authority(conn, monkeypatch, capsys):
    op = Operator(conn)
    pid = _fresh(conn, authority=False)
    factory = tf.FakeFactory(_fx())
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                           factory=factory)
    assert done == 1 and "no confirmed authority" in err
    assert factory.transports == []


def test_enrol_refuses_while_a_blocking_check_fails(conn, monkeypatch, capsys):
    from noctornal_api.http.routers import collection as router

    monkeypatch.setattr(router, "blocking_failures", lambda _c: ["security_officer_present"])
    op = Operator(conn)
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(_fresh(conn))],
                           factory=tf.FakeFactory(_fx()))
    assert done == 1 and err.startswith("This deployment is not ready to collect.")
    assert "security_officer_present" in err


def test_enrol_refuses_when_no_egress_proxy_is_configured(conn, monkeypatch, capsys):
    from noctornal_api import egress
    from noctornal_api.telegram import NO_PROXY_SENTENCE

    monkeypatch.setattr(egress, "boundary", lambda env=None: egress.Boundary(
        "DIRECT", None, False, ""))
    op = Operator(conn)
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(_fresh(conn))],
                           factory=tf.FakeFactory(_fx()))
    assert done == 1 and err.strip() == NO_PROXY_SENTENCE


def test_enrol_uses_short_connections_on_an_act_route_and_prints_one_line(
        conn, monkeypatch, capsys, tmp_path):
    from noctornal_api.collection import PersonaVault
    from noctornal_api.telegram import TelegramSecret

    monkeypatch.chdir(tmp_path)
    op = Operator(conn)
    pid = _fresh(conn)
    moved = tf.make_session(dc=4, ip="149.154.167.91")
    account = f"u:{tp.rand_id()}"
    factory = tf.FakeFactory(_fx(account), session_after=moved)
    done, out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                          factory=factory)
    assert done == 0, err
    first, second = factory.transports
    assert [c[0] for c in first.calls] == ["connect", "send_code", "close"]
    assert [c[0] for c in second.calls] == ["connect", "sign_in", "me", "close"]
    assert second.calls[1][1]["phone_code_hash"] == "phone-code-hash-1"
    assert second.secret.session == moved, "the second client starts from the first's session"
    assert all(p["username"].endswith(f"~act.{pid}") for p in factory.proxies)
    lines = out.splitlines()
    assert len(lines) == 1 and f"as Telegram account {account}" in lines[0]
    assert lines[0].endswith("Nothing secret was printed.")
    for secret_text in ("0123456789abcdef", "+447700900123", "12345 ", moved[:40]):
        assert secret_text not in out + err
    uid, enrolled_at, size, lock, _hold = _row(conn, pid)
    assert uid == account and enrolled_at is not None and size > 0 and lock is None
    with PersonaVault(conn).lease(pid, actor_id=None, purpose="check") as lease:
        assert TelegramSecret.parse(lease.value).session == moved
    audit = conn.execute(
        """SELECT actor_id, detail FROM audit.event
            WHERE action = 'PERSONA_SESSION_ENROLLED' AND object_id = %s""",
        (pid,)).fetchone()
    assert audit[0] == op.id and audit[1]["via"] == "scripts/telegram_persona.py"
    assert audit[1]["platform_uid"] == account and "host" in audit[1]
    assert not list(tmp_path.glob("*.session")), "no session file is written"


def test_a_two_step_password_is_asked_before_the_second_connection(conn, monkeypatch, capsys):
    op = Operator(conn)
    pid = _fresh(conn)
    factory = tf.FakeFactory(_fx(), password="hunter2-two-step")
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                           factory=factory, answers={"Two-step password": "hunter2-two-step"})
    assert done == 0, err
    assert "sign_in_password" in [c[0] for c in factory.transports[1].calls]
    missing = tf.FakeFactory(_fx(), password="hunter2-two-step")
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona",
                                                     str(_fresh(conn))], factory=missing)
    assert done == 1 and "two-step password" in err


def test_a_flood_wait_during_sign_in_holds_the_persona_before_the_unlock(
        conn, monkeypatch, capsys):
    from noctornal_api.telegram import TelegramFloodWait

    op = Operator(conn)
    pid = _fresh(conn)
    factory = tf.FakeFactory(_fx(), errors={"sign_in": TelegramFloodWait(30)})
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                           factory=factory)
    assert done == 1 and "asked this persona to wait" in err
    assert _row(conn, pid)[4] == "RATE_LIMITED"


def test_enrol_refuses_another_account_for_an_enrolled_persona(conn, monkeypatch, capsys):
    op = Operator(conn)
    pid, _e, uid = tp.persona(conn, P)
    _authority(conn, pid)
    done, _out, err = _run(monkeypatch, capsys, op,
                           ["enrol", "--persona", str(pid), "--replace"],
                           factory=tf.FakeFactory(_fx()))
    assert done == 1 and f"This persona is Telegram account {uid}" in err
    assert _row(conn, pid)[0] == uid


def test_enrol_refuses_a_persona_with_a_session_unless_replaced(conn, monkeypatch, capsys):
    op = Operator(conn)
    pid, _e, _uid = tp.persona(conn, P)
    _authority(conn, pid)
    done, _out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                           factory=tf.FakeFactory(_fx()))
    assert done == 1 and "--replace" in err


# --- import ---------------------------------------------------------------------------

def test_import_reads_stdin_never_argv(conn, monkeypatch, capsys):
    module = _script()
    with pytest.raises(SystemExit):
        module.main(["import", "--persona", "x", "--session", "abc"])
    capsys.readouterr()
    op = Operator(conn)
    pid = _fresh(conn)
    session = tf.make_session()
    account = f"u:{tp.rand_id()}"
    done, out, err = _run(monkeypatch, capsys, op, ["import", "--persona", str(pid)],
                          factory=tf.FakeFactory(_fx(account)),
                          stdin=json.dumps({"api_id": 1234567,
                                            "api_hash": "0123456789abcdef0123456789abcdef",
                                            "session": session}))
    assert done == 0, err
    assert account in out and session[:40] not in out
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                        "'PERSONA_SESSION_IMPORTED' AND object_id = %s",
                        (pid,)).fetchone()[0] == 1


@pytest.mark.parametrize("ip, port", [("10.0.0.5", 443), ("8.8.8.8", 443),
                                      ("149.154.167.51", 22)])
def test_import_refuses_a_session_pointing_outside_telegram(conn, monkeypatch, capsys,
                                                           ip, port):
    op = Operator(conn)
    pid = _fresh(conn)
    factory = tf.FakeFactory(_fx())
    done, _out, err = _run(monkeypatch, capsys, op, ["import", "--persona", str(pid)],
                           factory=factory,
                           stdin=json.dumps({"api_id": 1234567,
                                             "api_hash": "0123456789abcdef0123456789abcdef",
                                             "session": tf.make_session(ip=ip, port=port)}))
    assert done == 1 and "outside Telegram's published" in err
    assert factory.transports == []


# --- logout -------------------------------------------------------------------------------

def test_logout_runs_on_a_stop_route_without_an_authority_and_clears_then_destroys(
        conn, monkeypatch, capsys):
    op = Operator(conn)
    pid, _e, _uid = tp.persona(conn, P)
    factory = tf.FakeFactory(_fx())
    done, out, err = _run(monkeypatch, capsys, op,
                          ["logout", "--persona", str(pid), "--reason", "operation over"],
                          factory=factory)
    assert done == 0, err
    assert factory.proxies[0]["username"].endswith(f"~stop.{pid}")
    assert "log_out" in factory.methods()
    uid, enrolled_at, size, _lock, _hold = _row(conn, pid)
    assert enrolled_at is None and size == 0 and uid is not None
    detail = conn.execute("SELECT detail FROM audit.event WHERE action = 'PERSONA_LOGGED_OUT' "
                          "AND object_id = %s", (pid,)).fetchone()[0]
    assert detail["remote"] is True and detail["reason"] == "operation over"
    assert len(out.splitlines()) == 1


def test_logout_refuses_when_telegram_is_unreachable_unless_local_only(
        conn, monkeypatch, capsys):
    from noctornal_api.telegram import TelegramTransportFailed

    op = Operator(conn)
    pid, _e, _uid = tp.persona(conn, P)
    broken = tf.FakeFactory(_fx(), errors={"log_out": TelegramTransportFailed()})
    done, _out, err = _run(monkeypatch, capsys, op,
                           ["logout", "--persona", str(pid), "--reason", "operation over"],
                           factory=broken)
    assert done == 1 and "--local-only" in err
    assert _row(conn, pid)[2] > 0, "nothing destroyed"
    done, out, _err = _run(monkeypatch, capsys, op,
                           ["logout", "--persona", str(pid), "--reason", "operation over",
                            "--local-only"], factory=broken)
    assert done == 0 and "here only" in out
    assert _row(conn, pid)[2] == 0


def test_a_revoked_persona_is_logged_out_and_enrolled_again_through_the_script(
        conn, monkeypatch, capsys):
    """A persona Telegram locked
    could never be enrolled again. Log it out here, then enrol it: the
    enrolment gate admits a locked persona with no credential, and the new
    credential clears the lock."""
    from noctornal_api.collection import PersonaVault
    from noctornal_api.telegram import TelegramSessionRevoked

    op = Operator(conn)
    pid, _e, uid = tp.persona(conn, P)
    _authority(conn, pid)
    PersonaVault(conn).signal(pid, reason="revoked", lock_code="CREDENTIAL_REVOKED")
    dead = tf.FakeFactory(_fx(uid), errors={"log_out": TelegramSessionRevoked()})
    done, _out, err = _run(monkeypatch, capsys, op,
                           ["logout", "--persona", str(pid), "--reason", "session revoked",
                            "--local-only"], factory=dead)
    assert done == 0, err
    done, out, err = _run(monkeypatch, capsys, op, ["enrol", "--persona", str(pid)],
                          factory=tf.FakeFactory(_fx(uid)))
    assert done == 0, err
    assert f"as Telegram account {uid}" in out
    _uid, enrolled_at, size, lock, _hold = _row(conn, pid)
    assert lock is None and enrolled_at is not None and size > 0
