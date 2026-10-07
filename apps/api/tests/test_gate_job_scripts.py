"""The job scripts read what they are given and refuse what every job
refuses (beta 1 gate 6, 2026-10-07).

- `notify_drain.py --help` and `sandbox_dispatch.py --help` used to run the
  job: neither read its arguments, so asking for help sent the outbox, or the
  queued detonations. They take no options now, and say so.
- `retention_sweep.py` asked only for a published credential, and only on
  `--apply`: a dry run, or a real run holding the schema owner's DSN or the
  persona key, started where every other job refused. It makes the one
  refusal every job makes, first.

Pure: a connection is an error.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

from noctornal_api import config

ROOT = Path(__file__).resolve().parents[3]


class Connected(Exception):
    pass


def _boom(*_a, **_kw):
    raise Connected


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"gate65_{name}",
                                                  ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_notify_drain_help_is_help_and_drains_nothing(monkeypatch, capsys):
    module = _load("notify_drain")
    monkeypatch.setattr(module, "connect", _boom)
    monkeypatch.setattr(module, "dispatch_due", _boom)
    with pytest.raises(SystemExit) as done:
        module.main(["--help"])
    assert done.value.code == 0
    assert "usage:" in capsys.readouterr().out
    with pytest.raises(SystemExit) as done:
        module.main(["--now"])
    assert done.value.code == 2


def test_sandbox_dispatch_help_is_help_and_sends_nothing(monkeypatch, capsys):
    module = _load("sandbox_dispatch")
    from noctornal_api import sandbox
    monkeypatch.setattr(sandbox, "sandbox_settings", _boom)
    monkeypatch.setattr(sandbox, "dispatch_due", _boom)
    with pytest.raises(SystemExit) as done:
        module.main(["--help"])
    assert done.value.code == 0
    assert "usage:" in capsys.readouterr().out


def test_collection_poll_refuses_a_persona_key_boundary_with_exit_two(monkeypatch, capsys):
    """Production with no collector mark: the pass is refused with this job's
    sentence and code 2, where it was a traceback and 1, the code of a pass
    that ran and failed."""
    import sys

    from noctornal_api import egress_routes
    module = _load("collection_poll")
    monkeypatch.setattr(module, "connect", _boom)
    monkeypatch.setattr(egress_routes, "enforce_production_egress", lambda: None)
    monkeypatch.setattr(sys, "argv", ["collection_poll.py"])
    monkeypatch.setattr(os, "environ", {"NOCTORNAL_ENV": "production"})
    assert module.main() == config.JOB_REFUSAL_EXIT
    err = capsys.readouterr().err
    assert err.startswith("collection_poll: refusing to run: NOCTORNAL_ENV=production"), err
    assert "Traceback" not in err


@pytest.mark.parametrize("args", [[], ["--apply", "--actor", "a@b.example"]])
@pytest.mark.parametrize("variable, value", [
    ("NOCTORNAL_INGEST_PEPPER", "replace-me-ingest-pepper"),
    ("NOCTORNAL_MIGRATION_DATABASE_URL", "postgresql://noctornal:Xk9pQ7@db/noctornal"),
    ("NOCTORNAL_PERSONA_KEK", "A" * 44),
])
def test_the_retention_sweep_refuses_what_every_job_refuses_before_connecting(
        monkeypatch, capsys, args, variable, value):
    module = _load("retention_sweep")
    import noctornal_api.db as db
    monkeypatch.setattr(db, "connect_system", _boom)
    monkeypatch.setattr(os, "environ", {
        "NOCTORNAL_ENV": "production", variable: value,
        "NOCTORNAL_RETENTION_SWEEP_AUTHORITY": "RSW-2026-114 (records schedule 4.2)"})
    assert module.main(args) == config.JOB_REFUSAL_EXIT == 2
    err = capsys.readouterr().err
    assert err.startswith(f"retention_sweep: refusing to run: {variable}"), err
    assert value not in err
