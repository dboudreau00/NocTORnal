"""The jobs that are not the API refuse a credential the repository publishes
(infra-12, 2026-10-03; ROADMAP-REMAINING.md, "The cron jobs and a published
credential").

`config.verify_environment` stops the API on every published value, but the
cron scripts, the similarity pass and the migration job start without it and
did not look: with the template's placeholders they ran beside an API that
refused. `config.refuse_unsafe_job_environment` is the one helper each of them
calls first (merged with docs/17 F52's: it was `config.refuse_published` here,
which asked for the published half alone, and now asks for the schema owner's
credential as well; test_job_environment_refusals.py holds that half). It is
held here three ways: the helper alone, each script (refuses in production
before connecting to anything, and leaves development alone), and the migration
job through the real `alembic` command. The egress proxy, whose own database
password in the template is `replace-me`, and the preflight of its env files are
held at the bottom.

Pure: no database is reached (a refusal returns before any connection, and
the tests make a connection an error).
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from noctornal_api import config

ROOT = Path(__file__).resolve().parents[3]

PUBLISHED = "replace-me-ingest-pepper"


class Connected(Exception):
    """A script got as far as opening a connection."""


def _boom(*_args, **_kwargs):
    raise Connected


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"g48_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _environment(monkeypatch, **variables: str) -> None:
    """The process environment is exactly `variables`, a plain dict: the
    readers under test only `.get` it and walk its names."""
    monkeypatch.setattr(os, "environ", dict(variables))


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------

def test_the_helper_says_nothing_and_refuses_nothing_outside_production(monkeypatch):
    _environment(monkeypatch, NOCTORNAL_INGEST_PEPPER=PUBLISHED)
    assert config.refuse_unsafe_job_environment("job") == []
    _environment(monkeypatch, NOCTORNAL_ENV="development", NOCTORNAL_INGEST_PEPPER=PUBLISHED)
    assert config.refuse_unsafe_job_environment("job") == []


def test_the_helper_refuses_in_production_and_names_variables_never_values(monkeypatch):
    _environment(monkeypatch, NOCTORNAL_ENV=" Production ",
                 NOCTORNAL_INGEST_PEPPER=PUBLISHED,
                 SMTP_PASSWORD="prefix-dev_only_change_me-suffix")
    lines = config.refuse_unsafe_job_environment("job")
    # One line per variable, led by the job's name, where this build once
    # said both in a single line; the names are still all there, in order.
    assert len(lines) == 2, lines
    assert lines[0].startswith("job: refusing to run: NOCTORNAL_INGEST_PEPPER still carries "), lines
    assert lines[1].startswith("job: refusing to run: SMTP_PASSWORD still carries "), lines
    assert all(PUBLISHED not in line and "prefix" not in line for line in lines)


def test_the_helper_lets_a_clean_production_environment_through(monkeypatch):
    _environment(monkeypatch, NOCTORNAL_ENV="production",
                 NOCTORNAL_INGEST_PEPPER="9f2c1ad4e6b8a7d3c5e1",
                 DATABASE_URL="postgresql+psycopg://noctornal_app:Xk9pQ7@db:5432/noctornal")
    assert config.refuse_unsafe_job_environment("job") == []


# ---------------------------------------------------------------------------
# Each script
# ---------------------------------------------------------------------------

def _run_collection_poll(module):
    sys.argv = ["collection_poll.py"]
    return module.main()


def _run_notify_drain(module):
    return module.main()


def _run_embed_pass(module):
    return module.main([])


def _patch_connect(monkeypatch, module, name):
    if name == "lookup_drain":
        # It connects through noctornal_api.db, imported inside main().
        import noctornal_api.db as db
        monkeypatch.setattr(db, "connect_system", _boom)
    else:
        monkeypatch.setattr(module, "connect", _boom)


_SCRIPTS = {
    "collection_poll": _run_collection_poll,
    "notify_drain": _run_notify_drain,
    "embed_pass": _run_embed_pass,
    "lookup_drain": lambda module: module.main([]),
}


@pytest.mark.parametrize("name", sorted(_SCRIPTS))
def test_each_job_refuses_a_published_credential_in_production_before_connecting(
        name, monkeypatch, capsys):
    module = _load(name)
    _patch_connect(monkeypatch, module, name)
    monkeypatch.setattr(sys, "argv", sys.argv)
    _environment(monkeypatch, NOCTORNAL_ENV="production", NOCTORNAL_INGEST_PEPPER=PUBLISHED)
    assert _SCRIPTS[name](module) == config.JOB_REFUSAL_EXIT == 2
    seen = capsys.readouterr()
    # On stderr, one line per variable and led by the job's name, where this
    # build once printed one line on stdout (the helper that did is gone).
    assert seen.err.startswith(f"{name}: refusing to run: NOCTORNAL_INGEST_PEPPER still carries "), seen
    assert PUBLISHED not in seen.out + seen.err


@pytest.mark.parametrize("name", sorted(_SCRIPTS))
def test_each_job_is_unchanged_in_development(name, monkeypatch):
    """The other direction: a development stack runs on the published
    password by design, and the check must not reach it. The script gets as
    far as connecting, which the test makes the proof."""
    module = _load(name)
    _patch_connect(monkeypatch, module, name)
    monkeypatch.setattr(sys, "argv", sys.argv)
    _environment(monkeypatch, NOCTORNAL_INGEST_PEPPER=PUBLISHED)
    with pytest.raises(Connected):
        _SCRIPTS[name](module)


def test_the_lookup_drain_no_longer_carries_its_own_copy():
    text = (ROOT / "scripts" / "lookup_drain.py").read_text(encoding="utf-8")
    assert "refuse_unsafe_job_environment" in text and "published_credentials" not in text


# ---------------------------------------------------------------------------
# The migration job
# ---------------------------------------------------------------------------

def _alembic(env_extra: dict[str, str]) -> subprocess.CompletedProcess:
    # A minimal environment, not this process's: the development and CI
    # environments carry published passwords of their own (that is the point
    # of them), and the refusal would name those as well.
    keep = ("PATH", "SYSTEMROOT", "SystemRoot", "PYTHONPATH", "TEMP", "TMP", "TMPDIR",
            "HOME", "USERPROFILE", "VIRTUAL_ENV", "LD_LIBRARY_PATH")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.update(env_extra)
    return subprocess.run([sys.executable, "-m", "alembic", "current"], cwd=ROOT, env=env,
                          capture_output=True, text=True, encoding="utf-8", timeout=120)


def test_the_migration_job_refuses_a_published_credential_in_production():
    proc = _alembic({"NOCTORNAL_ENV": "production",
                     "DATABASE_URL": "postgresql+psycopg://noctornal:replace-me-owner@127.0.0.1:1/none"})
    assert proc.returncode == config.JOB_REFUSAL_EXIT, (proc.returncode, proc.stderr)
    assert "alembic: refusing to run: DATABASE_URL still carries" in proc.stderr
    assert "replace-me-owner" not in proc.stderr and "Traceback" not in proc.stderr


def test_the_migration_job_is_not_asked_in_development():
    """The same environment without NOCTORNAL_ENV goes on to connect, to a
    port nothing listens on, and fails there instead: a different error."""
    proc = _alembic({"DATABASE_URL": "postgresql+psycopg://noctornal:replace-me-owner"
                                     "@127.0.0.1:1/none?connect_timeout=2"})
    assert proc.returncode != 0
    assert "refusing to run" not in proc.stderr


# ---------------------------------------------------------------------------
# The egress proxy and its env files
# ---------------------------------------------------------------------------

def _proxy_environment(database_url: str) -> dict[str, str]:
    from noctornal_api.security import egress_seal
    keys = egress_seal.keygen()
    return {
        "NOCTORNAL_ENV": "production",
        "NOCTORNAL_EGRESS_LISTEN": "172.31.243.11:3128",
        "NOCTORNAL_EGRESS_INTERNAL_CIDRS": "172.31.243.0/24,172.31.244.0/24",
        "NOCTORNAL_EGRESS_DATABASE_URL": database_url,
        "NOCTORNAL_EGRESS_CLIENT_KEY": keys["NOCTORNAL_EGRESS_CLIENT_KEY"],
        "NOCTORNAL_EGRESS_SEAL_KEY": keys[egress_seal.SEAL_KEY_ENV],
        "NOCTORNAL_EGRESS_FINGERPRINT_KEY": keys[egress_seal.FINGERPRINT_KEY_ENV],
    }


def test_the_proxy_refuses_the_templates_database_password():
    from noctornal_api import egress_proxy
    env = _proxy_environment("postgresql://noctornal_egress:replace-me@postgres:5432/noctornal")
    problems = egress_proxy.verify_proxy_environment(env)
    assert len(problems) == 1, problems
    assert "NOCTORNAL_EGRESS_DATABASE_URL" in problems[0]
    assert "replace-me" in problems[0]  # the marker is named; the secret around it never is


def test_the_proxy_starts_on_a_password_that_is_not_published():
    from noctornal_api import egress_proxy
    env = _proxy_environment("postgresql://noctornal_egress:Xk9pQ7vWr2@postgres:5432/noctornal")
    assert egress_proxy.verify_proxy_environment(env) == []


def test_the_proxy_check_is_production_only():
    from noctornal_api import egress_proxy
    env = _proxy_environment("postgresql://noctornal_egress:replace-me@postgres:5432/noctornal")
    del env["NOCTORNAL_ENV"]
    assert not any("replace-me" in p for p in egress_proxy.verify_proxy_environment(env))


def _preflight_directory(tmp_path: Path, *, password: str) -> Path:
    from noctornal_api.security import egress_seal
    keys = egress_seal.keygen()
    files = {
        "egress-client.env": {k: keys[k] for k in ("NOCTORNAL_EGRESS_CLIENT_KEY",
                                                   "NOCTORNAL_EGRESS_FINGERPRINT_KEY",
                                                   "NOCTORNAL_EGRESS_SEAL_PUBLIC")},
        "egress-proxy.env": {
            "NOCTORNAL_EGRESS_DATABASE_URL":
                f"postgresql://noctornal_egress:{password}@postgres/noctornal",
            **{k: keys[k] for k in ("NOCTORNAL_EGRESS_CLIENT_KEY", "NOCTORNAL_EGRESS_SEAL_KEY",
                                    "NOCTORNAL_EGRESS_FINGERPRINT_KEY")}},
        "postgres-init.env": {"NOCTORNAL_EGRESS_DB_PASSWORD": password,
                              "NOCTORNAL_WORKER_DB_PASSWORD": "Qp7xL2vD9s"},
    }
    for name, values in files.items():
        (tmp_path / name).write_text("".join(f"{k}={v}\n" for k, v in values.items()),
                                     encoding="utf-8")
    return tmp_path


def _setup_script():
    spec = importlib.util.spec_from_file_location("g48_egress_setup",
                                                  ROOT / "scripts" / "egress_setup.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_preflight_refuses_a_template_password_that_agrees_in_both_files(tmp_path):
    """The two database passwords agreeing was the only thing checked, and
    `replace-me` agrees with itself."""
    directory = _preflight_directory(tmp_path, password="replace-me")
    problems = _setup_script().preflight(directory, compose=lambda: (2, 29))
    named = [p for p in problems if "carries" in p or "carry" in p]
    assert any(p.startswith("egress-proxy.env: NOCTORNAL_EGRESS_DATABASE_URL") for p in named), problems
    assert any(p.startswith("postgres-init.env: NOCTORNAL_EGRESS_DB_PASSWORD") for p in named), problems
    assert all("Qp7xL2vD9s" not in p for p in problems)


def test_preflight_passes_files_with_real_passwords(tmp_path):
    directory = _preflight_directory(tmp_path, password="Xk9pQ7vWr2")
    assert _setup_script().preflight(directory, compose=lambda: (2, 29)) == []
