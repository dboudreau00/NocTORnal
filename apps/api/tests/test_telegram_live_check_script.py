"""scripts/telegram_live_check.py: the Telegram end-to-end check, run here
as `--help` and as the self-check against the database with the Telegram
suite's fakes and no network (docs/17 F31, 2026-10-02).

DATABASE_URL-gated. Account, persona and source prefix `test-tglc-`.
"""
from __future__ import annotations

import importlib.util
import io
import os
import sys
from pathlib import Path

import pytest

import collection_helpers as h
import telegram_fake as tf
import telegram_pg as tp

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
pytest.importorskip("telethon")

P = "test-tglc-"
ROOT = Path(__file__).resolve().parents[3]


def _script():
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "telegram_live_check_script", ROOT / "scripts" / "telegram_live_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    from noctornal_api.http.routers import collection as router

    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_EGRESS_PROXY_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(router, "blocking_failures", lambda _c: [])
    tf.guard_sockets(monkeypatch)
    tf.patch_routes(monkeypatch)
    c = connect()
    yield c
    tp.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _world(conn, *, authority: bool = True, member: bool = False):
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    pid, egress, uid = tp.persona(conn, P)
    ch = tp.chat(conn, P, persona_id=pid, resolved_by=recorder,
                 access_mode="MEMBER" if member else "PUBLIC_READ",
                 peer_type="MEGAGROUP" if member else "CHANNEL",
                 member_since=member)
    if authority:
        h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=pid,
                    source_ids=[ch["source"]],
                    scope="MEMBER_READ" if member else "PUBLIC_READ",
                    member_ref="MEMBER-LIVE-CHECK-1" if member else None)
    return {"recorder": recorder, "persona": pid, "uid": uid, "chat": ch,
            "source": ch["source"]}


def _run(module, conn, persona, *, source=None, actor=None, factory=None):
    module.TRANSPORT_FACTORY = factory
    out = io.StringIO()
    code = module.run_check(conn, persona, source_id=source, self_check=True,
                            actor_id=actor, out=out)
    lines = out.getvalue().splitlines()
    return code, lines, {ln.split("] ", 1)[1].split(":")[0]: ln[1:5] for ln in lines}


def test_help_names_the_four_acts_and_promises_no_secret(capsys):
    module = _script()
    with pytest.raises(SystemExit) as done:
        module.main(["--help"])
    assert done.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    for words in ("enrolment", "read-only poll", "join check", "logout",
                  "no secret printed", "--self-check"):
        assert words in text, words
    assert "—" not in text and "–" not in text and "(s)" not in text


def test_the_self_check_proves_the_gates_and_routes_and_connects_to_nothing(conn):
    module = _script()
    w = _world(conn)
    code, lines, verdicts = _run(module, conn, w["persona"])
    assert code == 0, lines
    assert verdicts["environment"] == "PASS" and verdicts["persona"] == "PASS"
    assert verdicts["authority"] == "PASS" and verdicts["routes"] == "PASS"
    assert verdicts["operator"] == "SKIP"
    assert all(verdicts[s] == "SKIP" for s in ("enrolment", "poll", "join_check", "logout"))
    assert [ln.split("] ", 1)[1].split(":")[0] for ln in lines] == list(module.STEPS)
    audit = conn.execute(
        "SELECT actor_kind, outcome, detail FROM audit.event WHERE action = "
        "'TELEGRAM_LIVE_CHECK' AND object_id = %s", (w["persona"],)).fetchone()
    assert audit[0] == "SYSTEM" and audit[1] == "SUCCESS"
    assert audit[2]["self_check"] is True and len(audit[2]["steps"]) == len(module.STEPS)


def test_the_self_check_refuses_without_a_recorded_authority_and_names_it(conn):
    module = _script()
    w = _world(conn, authority=False)
    factory = tf.FakeFactory(tp.fixture_for(w["chat"]["spec"], w["uid"]))
    code, lines, verdicts = _run(module, conn, w["persona"], actor=w["recorder"],
                                 factory=factory)
    assert code == 1
    assert verdicts["authority"] == "FAIL"
    assert "no confirmed authority" in [ln for ln in lines if "authority" in ln][0].lower()
    assert "routes" not in verdicts and "poll" not in verdicts
    assert factory.transports == [], "nothing was built, let alone connected"


def test_the_self_check_refuses_a_persona_that_is_not_a_telegram_one(conn):
    module = _script()
    _world(conn)
    other = h.persona(conn, P, platform="XENFORO", egress=h.egress_profile(conn, P))
    code, _lines, verdicts = _run(module, conn, other)
    assert code == 1 and verdicts["persona"] == "FAIL"
    code, _lines, verdicts = _run(module, conn, h.persona(
        conn, P, platform="TELEGRAM", egress=h.egress_profile(conn, P)))
    assert code == 1 and verdicts["authority"] == "FAIL"


def test_the_self_check_exits_two_when_no_proxy_is_configured(conn, monkeypatch):
    from noctornal_api import egress

    module = _script()
    w = _world(conn)
    monkeypatch.delenv("NOCTORNAL_EGRESS_PROXY_URL", raising=False)
    monkeypatch.setattr(egress, "boundary", lambda env=None: egress.Boundary(
        "DIRECT", None, False, ""))
    code, _lines, verdicts = _run(module, conn, w["persona"])
    assert code == 2 and verdicts == {"environment": "FAIL"}


def test_with_the_fakes_the_four_acts_run_in_order_and_the_session_is_logged_out(conn):
    module = _script()
    w = _world(conn, member=True)
    fx = tp.fixture_for({**w["chat"]["spec"], "is_member": True}, w["uid"],
                        tp.messages(1, 3))
    factory = tf.FakeFactory(fx)
    code, lines, verdicts = _run(module, conn, w["persona"], actor=w["recorder"],
                                 factory=factory)
    assert code == 0, lines
    said = {ln.split("] ", 1)[1].split(":")[0]: ln for ln in lines}
    assert verdicts["enrolment"] == "PASS" and "already" in said["enrolment"]
    assert verdicts["poll"] == "PASS" and "3 items seen" in said["poll"]
    assert verdicts["join_check"] == "PASS" and "a member" in said["join_check"]
    assert "nothing was joined" in said["join_check"]
    assert verdicts["logout"] == "PASS"
    assert "operator" not in verdicts, "a named actor needs no sign-in prompt"
    assert "join" not in factory.methods(), "the join check never joins"
    assert "log_out" in factory.methods()
    assert all(p["username"].endswith((f"~run.{p['username'].split('.')[-1]}",
                                       f"~act.{w['persona']}", f"~stop.{w['persona']}"))
               for p in factory.proxies)
    kinds = {p["username"].split("~")[1].split(".")[0] for p in factory.proxies}
    assert kinds == {"run", "act", "stop"}
    # The credential is destroyed by the logout, and no secret was printed.
    held = conn.execute("SELECT octet_length(secret_ciphertext) FROM "
                        "collect.collection_account WHERE id = %s",
                        (w["persona"],)).fetchone()[0]
    assert held == 0
    text = "\n".join(lines)
    for secret_text in ("0123456789abcdef", tf.make_session()[:40], "phone-code"):
        assert secret_text not in text
    assert "[REDACTED]" not in text


def test_a_failing_poll_fails_the_check_and_still_logs_out(conn):
    from noctornal_api import telegram

    module = _script()
    w = _world(conn)
    fx = tp.fixture_for(w["chat"]["spec"], w["uid"], tp.messages(1, 2))
    factory = tf.FakeFactory(fx, errors={"open": telegram.TelegramSessionRevoked})
    code, lines, verdicts = _run(module, conn, w["persona"], actor=w["recorder"],
                                 factory=factory)
    assert code == 1, lines
    assert verdicts["poll"] == "FAIL" and "join_check" not in verdicts
    assert verdicts["logout"] in ("PASS", "FAIL")
    audit = conn.execute(
        "SELECT outcome FROM audit.event WHERE action = 'TELEGRAM_LIVE_CHECK' "
        "AND object_id = %s", (w["persona"],)).fetchone()
    assert audit[0] == "FAILED"


def test_an_unattended_exception_prints_its_class_and_never_its_text():
    """2026-10-03: the module promises never a library's
    text, and the redactor masks neither a bare phone number nor an address
    with a user name."""
    module = _script()
    for text in ("The phone number +15551234567 is invalid",
                 "socks5://u~r:pw@127.0.0.1:1080 refused"):
        said = module._sentence(RuntimeError(text))
        assert "RuntimeError" in said
        assert "15551234567" not in said and "pw@" not in said and "socks5" not in said
