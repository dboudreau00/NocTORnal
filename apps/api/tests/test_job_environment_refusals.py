"""Every cron job refuses the schema owner's credential and a published one
(docs/17 F52 and ROADMAP-REMAINING's "The cron jobs and a published
credential", 2026-10-02).

The 2026-10-02 review of F52 found that in a mixed layout (migrate.env in
place, the owner's line still, or again, in secrets.env) the migrate job
ran, the API refused, and cron and embed-pass started holding the owner's
password and DSN with no check at all. Held here:

* `config.refuse_unsafe_job_environment` is the one helper, production
  only, one line per variable, never a value, and one refusal per variable;
* notify_drain, collection_poll, lookup_drain and embed_pass call it before
  they connect to anything, each with its own documented exit code;
* the Lab's three workers, which call `enforce_environment`, refuse the
  owner's credential through it.

No database: every script is stopped before it could connect, and the test
fails if it tries.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from noctornal_api import config
from test_config_boot import _production

ROOT = Path(__file__).resolve().parents[3]
OWNER_PASSWORD = "Hq7vX2-owner"
OWNER_DSN = f"postgresql+psycopg://noctornal:{OWNER_PASSWORD}@postgres:5432/noctornal"

#: (script, the exit code its docstring gives a refusal)
CRON_JOBS = [("notify_drain", 2), ("collection_poll", 1), ("lookup_drain", 2),
             ("embed_pass", 1)]
LAB_WORKERS = ["lab_triage", "sample_screen", "sandbox_dispatch"]


def _script(name: str):
    spec = importlib.util.spec_from_file_location(f"g32_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _no_connection(monkeypatch, module) -> None:
    """Any way the script could open a database connection fails the test:
    the refusal has to come first."""
    import noctornal_api.db as db

    def connected(*_a, **_k):
        raise AssertionError("connected before the environment check")

    for target in (module, db):
        for name in ("connect", "connect_system"):
            if hasattr(target, name):
                monkeypatch.setattr(target, name, connected)


def _production_process(monkeypatch, **extra: str) -> None:
    """This process's environment as a clean production one, plus `extra`.
    The runner's own published values (the development password in
    DATABASE_URL, CI's KEK) are taken out, so a refusal can only come
    from what the test put in."""
    for name, value in _production().items():
        monkeypatch.setenv(name, value)
    for found in config.published_credentials():
        monkeypatch.delenv(found.variable, raising=False)
    for name in (config.OWNER_PASSWORD_ENV, config.MIGRATION_DSN_ENV):
        monkeypatch.delenv(name, raising=False)
    for name, value in extra.items():
        monkeypatch.setenv(name, value)


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------

def test_a_clean_production_environment_runs():
    assert config.refuse_unsafe_job_environment("notify_drain", _production()) == []


@pytest.mark.parametrize("name, value, home", [
    (config.OWNER_PASSWORD_ENV, OWNER_PASSWORD, "postgres-init.env"),
    (config.MIGRATION_DSN_ENV, OWNER_DSN, "migrate.env"),
])
def test_the_owner_credential_is_refused_by_name_never_by_value(name, value, home):
    env = {**_production(), name: value}
    (line,) = config.refuse_unsafe_job_environment("embed_pass", env)
    assert line.startswith(f"embed_pass: refusing to run: {name} is set on a runtime process")
    assert home in line and "sudo ./release/install.sh --production-secrets" in line
    assert config.SECRETS_UPGRADE_NOTE in line
    assert OWNER_PASSWORD not in line


def test_a_published_credential_is_refused():
    env = {**_production(), "MINIO_SECRET_KEY": config.DEV_CREDENTIAL}
    (line,) = config.refuse_unsafe_job_environment("collection_poll", env)
    assert line.startswith("collection_poll: refusing to run: MINIO_SECRET_KEY still carries")


def test_one_variable_one_refusal():
    """A published owner password is refused for its value, once."""
    env = {**_production(), config.OWNER_PASSWORD_ENV: "replace-me-owner-password",
           config.MIGRATION_DSN_ENV: OWNER_DSN}
    lines = config.refuse_unsafe_job_environment("lookup_drain", env)
    assert len(lines) == 2, lines
    assert sum(config.OWNER_PASSWORD_ENV in line for line in lines) == 1
    assert any("placeholder" in line for line in lines)


def test_empty_counts_as_unset():
    """What every runtime service's `environment:` block sets (compose.yml)."""
    env = {**_production(), config.OWNER_PASSWORD_ENV: "", config.MIGRATION_DSN_ENV: " "}
    assert config.refuse_unsafe_job_environment("notify_drain", env) == []


def test_development_is_left_alone():
    env = {**_production(), "NOCTORNAL_ENV": "development",
           config.OWNER_PASSWORD_ENV: OWNER_PASSWORD,
           "MINIO_SECRET_KEY": config.DEV_CREDENTIAL}
    assert config.refuse_unsafe_job_environment("notify_drain", env) == []
    del env["NOCTORNAL_ENV"]
    assert config.refuse_unsafe_job_environment("notify_drain", env) == []


# ---------------------------------------------------------------------------
# Each cron job calls it, before it connects
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("job, code", CRON_JOBS)
@pytest.mark.parametrize("name, value", [
    (config.OWNER_PASSWORD_ENV, OWNER_PASSWORD),
    (config.MIGRATION_DSN_ENV, OWNER_DSN),
])
def test_each_cron_job_refuses_the_owner_credential_before_connecting(
        job, code, name, value, monkeypatch, capsys):
    module = _script(job)
    _production_process(monkeypatch, **{name: value})
    _no_connection(monkeypatch, module)
    assert module.main() == code
    out = capsys.readouterr()
    assert out.err.splitlines() == [
        line for line in config.refuse_unsafe_job_environment(job)]
    assert out.err.startswith(f"{job}: refusing to run: {name} is set on a runtime process")
    assert OWNER_PASSWORD not in out.out + out.err


@pytest.mark.parametrize("job, code", CRON_JOBS)
def test_each_cron_job_refuses_a_published_credential_before_connecting(
        job, code, monkeypatch, capsys):
    module = _script(job)
    _production_process(monkeypatch, SMTP_PASSWORD="replace-me-smtp-password")
    _no_connection(monkeypatch, module)
    assert module.main() == code
    err = capsys.readouterr().err
    assert err.startswith(f"{job}: refusing to run: SMTP_PASSWORD still carries")


def test_the_cron_jobs_are_every_script_the_cron_loops_run():
    """A job added to a compose loop joins the list above, or this fails."""
    import re
    compose = (ROOT / "infra" / "production" / "compose.yml").read_text(encoding="utf-8")
    run = set(re.findall(r"python scripts/(\w+)\.py", compose))
    assert run == {job for job, _ in CRON_JOBS} | set(LAB_WORKERS), run


# ---------------------------------------------------------------------------
# The Lab's workers refuse it through enforce_environment
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("worker", LAB_WORKERS)
def test_each_lab_worker_refuses_the_owner_credential_before_connecting(worker, monkeypatch):
    module = _script(worker)
    _production_process(monkeypatch, **{config.OWNER_PASSWORD_ENV: OWNER_PASSWORD})
    _no_connection(monkeypatch, module)
    with pytest.raises(RuntimeError) as refused:
        module.main([])
    message = str(refused.value)
    assert f"{config.OWNER_PASSWORD_ENV} is set on a runtime process" in message
    assert OWNER_PASSWORD not in message
