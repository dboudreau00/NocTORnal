"""The mail stamp key ring in the deployment: the boot check, the readiness row, the egress proxy's refusal
and the sample origin's blank (docs/19 section 2.1).

No database: the readiness probe reads the environment only.
"""
from __future__ import annotations

import base64

import pytest

from mail_stamp_support import KEY
from noctornal_api import config, mail_stamp, readiness
from test_config_boot import _only, _production

ENV_NAMES = (mail_stamp.KEY_ENV, mail_stamp.KEY_ID_ENV, mail_stamp.RETIRED_ENV)
SHORT = base64.b64encode(KEY[:8]).decode()
GOOD = base64.b64encode(KEY).decode()


@pytest.fixture
def clean_env(monkeypatch):
    for name in ENV_NAMES + ("NOCTORNAL_TRUSTED_MTA_HOSTS",):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_a_malformed_mail_stamp_ring_is_a_boot_refusal_in_production_and_an_unset_one_is_not():
    assert config.verify_environment(_production()) == []
    env = _production()
    env[mail_stamp.KEY_ENV] = SHORT
    problem = _only(config.verify_environment(env), mail_stamp.KEY_ENV)
    assert "sender's claim" in problem
    assert SHORT not in problem
    env[mail_stamp.KEY_ENV] = GOOD
    env[mail_stamp.RETIRED_ENV] = "mail:v0=" + SHORT
    problem = _only(config.verify_environment(env), mail_stamp.RETIRED_ENV)
    assert SHORT not in problem and GOOD not in problem


def test_a_usable_ring_boots():
    env = _production()
    env[mail_stamp.KEY_ENV] = GOOD
    env[mail_stamp.KEY_ID_ENV] = "mail:v2"
    assert config.verify_environment(env) == []


def test_the_readiness_row_is_ok_with_a_caveat_when_no_key_is_set_and_never_blocking(clean_env):
    assert "mail_stamp_key" in readiness.CHECK_NAMES
    assert readiness.CHECK_NAMES[-1] == "mail_stamp_key"
    assert "mail_stamp_key" not in readiness.BLOCKING_CHECKS
    row = readiness._mail_stamp_key(None)
    assert row.ok and row.check == "mail_stamp_key"
    assert "sender's claim" in row.caveat


def test_the_readiness_row_fails_on_an_unreadable_ring_without_quoting_it(clean_env):
    clean_env.setenv(mail_stamp.KEY_ENV, SHORT)
    row = readiness._mail_stamp_key(None)
    assert not row.ok and row.action
    assert SHORT not in row.evidence + row.action


def test_the_readiness_row_names_the_active_id_and_says_when_no_mta_is_declared(clean_env):
    clean_env.setenv(mail_stamp.KEY_ENV, GOOD)
    clean_env.setenv(mail_stamp.KEY_ID_ENV, "mail:v2")
    clean_env.setenv(mail_stamp.RETIRED_ENV, "mail:v1=" + base64.b64encode(bytes(32)).decode())
    row = readiness._mail_stamp_key(None)
    assert row.ok and row.evidence == "active key id mail:v2, 1 retired key"
    assert "No trusted MTA host is declared" in row.caveat
    assert GOOD not in row.evidence + row.caveat
    clean_env.setenv("NOCTORNAL_TRUSTED_MTA_HOSTS", "corp.example")
    row = readiness._mail_stamp_key(None)
    assert row.ok and row.caveat == ""


def test_the_proxy_refuses_to_hold_the_mail_stamp_key():
    from noctornal_api import egress_proxy
    from test_egress_refusals import _proxy_env

    for name in (mail_stamp.KEY_ENV, mail_stamp.RETIRED_ENV):
        assert name in egress_proxy.FORBIDDEN_ENV
        problems = egress_proxy.verify_proxy_environment(_proxy_env(**{name: GOOD}))
        assert any(name in p for p in problems), problems
        assert not any(GOOD in p for p in problems)


def test_the_sample_origin_blanks_the_mail_stamp_key():
    from test_egress_topology import COMPOSE, Reader

    doc = Reader(COMPOSE.read_text(encoding="utf-8")).document()
    env = doc["services"]["sample-origin"]["environment"]
    assert env[mail_stamp.KEY_ENV] == "" and env[mail_stamp.RETIRED_ENV] == ""
