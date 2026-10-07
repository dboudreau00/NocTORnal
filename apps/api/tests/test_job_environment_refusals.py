"""Every cron job refuses the schema owner's credential and a published one
(docs/17 F52 and ROADMAP-REMAINING's "The cron jobs and a published
credential", 2026-10-02).

The 2026-10-02 review of F52 found that in a mixed layout (migrate.env in
place, the owner's line still, or again, in secrets.env) the migrate job
ran, the API refused, and cron and embed-pass started holding the owner's
password and DSN with no check at all. Held here:

* `config.refuse_unsafe_job_environment` is the one helper, production
  only, one line per variable, never a value, and one refusal per variable;
  it asks for the owner's credential and for a published one, and the
  migration job, which holds the owner's DSN by design, is asked for the
  published half alone;
* notify_drain, collection_poll, lookup_drain, embed_pass and the collector
  (scripts/collector.py, A collector process, 2026-10-02) call it once,
  first, before they connect to anything, and all five exit
  `config.JOB_REFUSAL_EXIT` (2: 1 means a pass ran and failed). Merged from
  two builds that disagreed on the code (docs/17 F52 gave collection_poll and
  embed_pass 1; infra-12 gave all four 2) and on the helper that made the
  published half (`config.refuse_published`, now gone);
* a job that is not the collector also refuses the persona key and the
  collector's mark, through the same helper (the collector and the poll it
  starts as a child pass `holds_persona_key=True`: the key is theirs by
  design, and each makes the collector's own half itself);
* the Lab's three workers ask the same helper for the API's whole production
  list (`whole_environment=True`), and refuse the owner's credential, a
  published one and the rest of that list the way every other job does: one
  line per problem on stderr led by the job's name, exit 2 and no traceback.
  They called `enforce_environment`, whose RuntimeError was exit 1 with a
  traceback (Beta 1 verification, 2026-10-07).

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

#: (script, the exit code its docstring gives a refusal): one code for all.
CRON_JOBS = [(name, config.JOB_REFUSAL_EXIT)
             for name in ("notify_drain", "collection_poll", "lookup_drain", "embed_pass",
                          "collector")]
LAB_WORKERS = ["lab_triage", "sample_screen", "sandbox_dispatch"]
#: The jobs that hold the persona key by design (A collector process,
#: 2026-10-02): the collector, and the poll it starts as its child. The
#: poll is not a line of any compose loop, so it is not in the compose scan.
KEY_HOLDERS = ("collector", "collection_poll")
COLLECTOR_CHILDREN = ("collection_poll",)


def _expected(job: str) -> list[str]:
    """What the helper says to `job` in this process's environment."""
    return config.refuse_unsafe_job_environment(job, holds_persona_key=job in KEY_HOLDERS)


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


def test_several_published_credentials_are_one_line_each_naming_no_value():
    """Said by infra-12's own test before the two helpers were one: the
    production mode is read however it is spelled, every published variable
    is named, and a published value is never quoted, nor what surrounds it."""
    env = {**_production(), "NOCTORNAL_ENV": " Production ",
           "NOCTORNAL_INGEST_PEPPER": "replace-me-ingest-pepper",
           "SMTP_PASSWORD": "prefix-dev_only_change_me-suffix"}
    lines = config.refuse_unsafe_job_environment("embed_pass", env)
    assert [line.split(" still carries")[0] for line in lines] == [
        "embed_pass: refusing to run: NOCTORNAL_INGEST_PEPPER",
        "embed_pass: refusing to run: SMTP_PASSWORD"], lines
    assert not any("replace-me-ingest-pepper" in line or "prefix" in line for line in lines)


def test_the_migration_job_is_not_asked_for_the_owner_half_but_is_for_the_published_half():
    """The one job that connects as the schema owner holds the owner's DSN
    because that is its work; a published value anywhere in its environment,
    the DSN's own password included, still refuses it."""
    env = {**_production(), config.MIGRATION_DSN_ENV: OWNER_DSN,
           config.OWNER_PASSWORD_ENV: OWNER_PASSWORD}
    assert config.refuse_unsafe_job_environment(
        "migrate", env, holds_owner_credential=True) == []
    assert len(config.refuse_unsafe_job_environment("migrate", env)) == 2
    env["SMTP_PASSWORD"] = "replace-me-smtp-password"
    (line,) = config.refuse_unsafe_job_environment(
        "migrate", env, holds_owner_credential=True)
    assert line.startswith("migrate: refusing to run: SMTP_PASSWORD still carries")
    env = {**_production(), config.MIGRATION_DSN_ENV:
           "postgresql+psycopg://noctornal:replace-me-owner-password@postgres:5432/noctornal"}
    (line,) = config.refuse_unsafe_job_environment(
        "migrate", env, holds_owner_credential=True)
    assert config.MIGRATION_DSN_ENV in line and "replace-me-owner-password" not in line


def test_the_migration_job_problems_come_from_the_same_helper():
    """`migration_job_problems` asks the whole environment, not the DSN
    alone, through the helper every other job calls."""
    env = {"NOCTORNAL_ENV": "production", config.MIGRATION_DSN_ENV: OWNER_DSN,
           "SMTP_PASSWORD": "replace-me-smtp-password"}
    (line,) = config.migration_job_problems(env)
    assert line.startswith("migrate: refusing to run: SMTP_PASSWORD still carries")
    del env["SMTP_PASSWORD"]
    assert config.migration_job_problems(env) == []


def test_there_is_one_job_helper_and_it_is_called_once_in_each_job():
    """The merge of two builds left two helpers and two call patterns in each
    script; a second helper, or a second call, fails here."""
    assert not hasattr(config, "refuse_published")
    assert not hasattr(config, "PUBLISHED_REFUSAL_EXIT")
    for path in ("scripts/notify_drain.py", "scripts/collection_poll.py",
                 "scripts/lookup_drain.py", "scripts/embed_pass.py",
                 "scripts/collector.py", "db/migrations/env.py"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert text.count("refuse_unsafe_job_environment(") == 1, path
        assert "refuse_published" not in text and "published_credentials" not in text, path
    # The migration job reaches the helper through migration_job_problems.
    job = (ROOT / "scripts" / "migrate_job.py").read_text(encoding="utf-8")
    assert job.count("migration_job_problems(") == 1
    assert "refuse_published" not in job


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
    assert out.err.splitlines() == _expected(job)
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
    # The collection poll runs as the collector's child, not in a loop.
    assert run == ({job for job, _ in CRON_JOBS} - set(COLLECTOR_CHILDREN)) | set(LAB_WORKERS), run
    collector = (ROOT / "scripts" / "collector.py").read_text(encoding="utf-8")
    assert all(f"{child}.py" in collector for child in COLLECTOR_CHILDREN)


# ---------------------------------------------------------------------------
# The persona key (A collector process, 2026-10-02)
# ---------------------------------------------------------------------------

PERSONA_KEY = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="


def test_a_job_that_is_not_the_collector_refuses_the_persona_key_by_name_never_by_value():
    env = {**_production(), "NOCTORNAL_PERSONA_KEK": PERSONA_KEY}
    for job in ("notify_drain", "lookup_drain", "embed_pass", "migrate"):
        (line,) = config.refuse_unsafe_job_environment(job, env, holds_owner_credential=job == "migrate")
        assert line.startswith(f"{job}: refusing to run: NOCTORNAL_PERSONA_KEK ")
        assert "not the collector" in line and PERSONA_KEY not in line
    marked = {**_production(), "NOCTORNAL_COLLECTOR": "1"}
    (line,) = config.refuse_unsafe_job_environment("notify_drain", marked)
    assert "NOCTORNAL_COLLECTOR is set on a process that is not the collector" in line
    inline = {**_production(), "NOCTORNAL_COLLECTOR_INLINE": "1"}
    (line,) = config.refuse_unsafe_job_environment("lookup_drain", inline)
    assert "development only" in line


def test_the_collector_and_its_poll_are_not_asked_for_the_key_they_are_there_to_hold():
    env = {**_production(), "NOCTORNAL_PERSONA_KEK": PERSONA_KEY, "NOCTORNAL_COLLECTOR": "1"}
    for job in KEY_HOLDERS:
        assert config.refuse_unsafe_job_environment(job, env, holds_persona_key=True) == []
    # ... but the rest of the helper still applies to them: the collector never
    # receives the schema owner's credential, nor a published one.
    owner = {**env, config.OWNER_PASSWORD_ENV: OWNER_PASSWORD}
    (line,) = config.refuse_unsafe_job_environment("collector", owner, holds_persona_key=True)
    assert line.startswith(f"collector: refusing to run: {config.OWNER_PASSWORD_ENV} is set")
    published = {**env, "SMTP_PASSWORD": "replace-me-smtp-password"}
    (line,) = config.refuse_unsafe_job_environment("collector", published, holds_persona_key=True)
    assert line.startswith("collector: refusing to run: SMTP_PASSWORD still carries")


def test_the_persona_key_is_nobodys_business_outside_production():
    env = {"NOCTORNAL_ENV": "development", "NOCTORNAL_PERSONA_KEK": PERSONA_KEY,
           "NOCTORNAL_COLLECTOR_INLINE": "1"}
    assert config.refuse_unsafe_job_environment("notify_drain", env) == []


# ---------------------------------------------------------------------------
# The Lab's workers refuse it through the same helper, asked for the whole list
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("worker", LAB_WORKERS)
def test_each_lab_worker_refuses_the_owner_credential_before_connecting(
        worker, monkeypatch, capsys):
    module = _script(worker)
    _production_process(monkeypatch, **{config.OWNER_PASSWORD_ENV: OWNER_PASSWORD})
    _no_connection(monkeypatch, module)
    assert module.main([]) == config.JOB_REFUSAL_EXIT == 2
    out = capsys.readouterr()
    assert out.err.splitlines() == config.refuse_unsafe_job_environment(worker, whole_environment=True)
    assert any(line.startswith(
        f"{worker}: refusing to run: {config.OWNER_PASSWORD_ENV} is set on a runtime process")
        for line in out.err.splitlines()), out.err
    assert "Traceback" not in out.out + out.err
    assert OWNER_PASSWORD not in out.out + out.err


@pytest.mark.parametrize("worker", LAB_WORKERS)
def test_each_lab_worker_refuses_a_published_credential_before_connecting(
        worker, monkeypatch, capsys):
    module = _script(worker)
    _production_process(monkeypatch, SMTP_PASSWORD="replace-me-smtp-password")
    _no_connection(monkeypatch, module)
    assert module.main([]) == config.JOB_REFUSAL_EXIT
    err = capsys.readouterr().err
    assert any(line.startswith(f"{worker}: refusing to run: SMTP_PASSWORD still carries")
               for line in err.splitlines()), err
    assert "replace-me-smtp-password" not in err


@pytest.mark.parametrize("worker", LAB_WORKERS)
def test_each_lab_worker_still_makes_the_checks_only_the_whole_list_has(
        worker, monkeypatch, capsys):
    """The workers hold the sample store's credentials and the key ring, so
    they keep every refusal the API makes, not only the three the cron jobs
    ask for: an unset sample-store credential is one only the whole list makes."""
    module = _script(worker)
    _production_process(monkeypatch)
    monkeypatch.delenv("SAMPLE_ACCESS_KEY", raising=False)
    assert not any("SAMPLE_ACCESS_KEY" in line for line in
                   config.refuse_unsafe_job_environment(worker)), "the narrow helper does not ask"
    _no_connection(monkeypatch, module)
    assert module.main([]) == config.JOB_REFUSAL_EXIT
    assert f"{worker}: refusing to run: SAMPLE_ACCESS_KEY is not set" in capsys.readouterr().err


def test_the_whole_environment_is_verify_environments_list_one_line_each():
    env = {**_production(), "SMTP_PASSWORD": "replace-me-smtp-password"}
    whole = config.refuse_unsafe_job_environment("lab_triage", env, whole_environment=True)
    assert whole == [f"lab_triage: refusing to run: {p}" for p in config.verify_environment(env)]
    assert any(line.startswith("lab_triage: refusing to run: SMTP_PASSWORD still carries")
               for line in whole)
    assert not any("replace-me-smtp-password" in line for line in whole)
    assert config.refuse_unsafe_job_environment(
        "lab_triage", {**env, "NOCTORNAL_ENV": "development"}, whole_environment=True) == []
    assert config.refuse_unsafe_job_environment("lab_triage", _production(), whole_environment=True) == []


@pytest.mark.parametrize("worker", LAB_WORKERS)
def test_a_lab_worker_calls_the_one_helper_once_and_no_longer_raises(worker):
    text = (ROOT / "scripts" / f"{worker}.py").read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert text.count("refuse_unsafe_job_environment(") == 1, worker
    assert 'whole_environment=True' in code and "return JOB_REFUSAL_EXIT" in code
    assert "enforce_environment(" not in code, "a RuntimeError is exit 1 with a traceback"
