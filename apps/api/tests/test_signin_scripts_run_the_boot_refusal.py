"""The two scripts that sign an operator in run the boot refusal first (the independent review TRANSPORT-05).

scripts/telegram_persona.py and scripts/egress_setup.py record a failed sign-in through
`audit_hash.typed_identifier`, keyed under NOCTORNAL_AUDIT_PEPPER, and neither asked whether the
environment is one the services would start in. In production each now runs `config.verify_environment`
(the collector's, for the persona script, which runs in the collector) before it asks anybody for
anything or opens a connection, and refuses on a pepper the API refuses: short, a copy of another
secret or a published placeholder. Outside production nothing changes.

Pure: the prompts and the connection raise if they are reached.
"""
from __future__ import annotations

import builtins
import getpass
import importlib.util
import sys
import uuid
from pathlib import Path

import pytest
from test_config_boot import _production

from noctornal_api import config

ROOT = Path(__file__).resolve().parents[3]
SHORT = "Sh0rt-pepper-15"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    return module


def _asked(*_a, **_k):
    raise AssertionError("somebody was asked for something, or a connection was opened")


@pytest.fixture
def production_with_a_short_pepper(monkeypatch):
    for name, value in _production().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("NOCTORNAL_AUDIT_PEPPER", SHORT)
    monkeypatch.setattr(builtins, "input", _asked)
    monkeypatch.setattr(getpass, "getpass", _asked)
    return monkeypatch


def test_the_persona_script_refuses_before_asking_where_the_collector_would_not_start(
        production_with_a_short_pepper, capsys):
    monkeypatch = production_with_a_short_pepper
    script = _load("telegram_persona")
    monkeypatch.setattr(script, "load_env_local", lambda: None)
    monkeypatch.setattr(script, "sign_in", _asked)
    # The persona boundary is its own refusal, tested in test_persona_key_split.py; past it, the rest of
    # the collector's start refusal must still stop the script.
    monkeypatch.setattr(config, "enforce_persona_key_boundary", lambda **_k: None)
    from noctornal_api import db
    monkeypatch.setattr(db, "connect_system", _asked)
    assert script.main(["enrol", "--persona", str(uuid.uuid4())]) == 2
    err = capsys.readouterr().err
    assert err.startswith("This environment would not start the collector, so nothing was asked")
    assert "NOCTORNAL_AUDIT_PEPPER is 15 characters, fewer than 16" in err
    assert SHORT not in err and "Traceback" not in err


@pytest.mark.parametrize("argv", [["list"], ["route-create", "--name", "n", "--description", "d"]])
def test_the_egress_script_refuses_before_signing_in_where_the_api_would_not_start(
        production_with_a_short_pepper, argv):
    monkeypatch = production_with_a_short_pepper
    script = _load("egress_setup")
    monkeypatch.setattr(script, "_connect", _asked)
    with pytest.raises(script.SetupError) as refused:
        script.run(argv, ask=_asked, secret=_asked)
    said = str(refused.value)
    assert said.startswith("This environment would not start the API, so nobody was asked")
    assert config.verify_environment() and all(p in said for p in config.verify_environment())
    assert "NOCTORNAL_AUDIT_PEPPER is 15 characters, fewer than 16" in said and SHORT not in said


def test_the_egress_commands_that_read_no_database_still_run_before_the_keys_exist(
        production_with_a_short_pepper):
    """keygen runs before the egress keys exist, and the API's own refusal would ask for them."""
    script = _load("egress_setup")
    production_with_a_short_pepper.setattr(script, "_connect", _asked)
    out: list[str] = []
    assert script.run(["role-sql"], ask=_asked, secret=_asked, out=out.append) == 0
    assert out
