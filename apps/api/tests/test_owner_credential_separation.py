"""The schema owner's credential reaches no runtime service (docs/17 F52,
2026-10-02).

The owner `noctornal` is the Postgres image's bootstrap superuser: row-level
security does not bind it, and it can switch off the append-only triggers.
Its password (POSTGRES_PASSWORD) and DSN (NOCTORNAL_MIGRATION_DATABASE_URL)
sat in infra/production/secrets.env, which every application service and
caddy read. Held here:

* the production compose file gives the owner's password to postgres alone
  (postgres-init.env) and its DSN to the migrate job alone (migrate.env),
  and the migrate job reads nothing else;
* the templates put each where it now lives and nowhere else;
* the API refuses to start holding either, by name and never by value;
* the migration job refuses without its DSN, naming the installer step,
  and refuses a published owner password, which the API used to refuse
  while it could see it;
* no secrets file, nor a backup of one, reaches the image or git.

Pure: no database, no Docker.
"""
from __future__ import annotations

import fnmatch
import importlib.util
import io
import re
from pathlib import Path

import pytest

from noctornal_api import config
from test_config_boot import _only, _production
from test_egress_topology import Reader, _env_files

ROOT = Path(__file__).resolve().parents[3]
PROD = ROOT / "infra" / "production"
OWNER_DSN = "postgresql+psycopg://noctornal:Hq7vX2-owner@postgres:5432/noctornal"
OWNER_PASSWORD = "Hq7vX2-owner"


@pytest.fixture(scope="module")
def services():
    return Reader((PROD / "compose.yml").read_text(encoding="utf-8")).document()["services"]


def _assignments(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
        if match:
            out[match.group(1)] = match.group(2)
    return out


# ---------------------------------------------------------------------------
# The compose file and the templates
# ---------------------------------------------------------------------------

def test_the_migrate_job_reads_migrate_env_and_nothing_else(services):
    migrate = services["migrate"]
    assert _env_files(migrate) == [("migrate.env", False)]
    assert migrate["command"] == ["python", "scripts/migrate_job.py"]
    assert migrate["environment"]["NOCTORNAL_ENV"] == "production"


def test_only_the_migrate_job_reads_migrate_env(services):
    readers = {name for name, svc in services.items()
               if "migrate.env" in dict(_env_files(svc))}
    assert readers == {"migrate"}


def test_every_other_application_service_keeps_secrets_env(services):
    """The move is out of secrets.env, not a second copy of it: the API
    and the loops still read secrets.env and nothing owner-shaped."""
    for name in ("api", "sample-origin", "cron", "lab-triage", "lab-cron", "embed-pass"):
        files = dict(_env_files(services[name]))
        assert "secrets.env" in files and "migrate.env" not in files, name
        assert "postgres-init.env" not in files, name


def test_every_runtime_service_holds_the_owner_variables_blank(services):
    """Enforced, not conventional (review of 2026-10-02): in a mixed layout,
    migrate.env in place and the owner's line still or again in
    secrets.env, cron and embed-pass started holding the owner's password
    and DSN, since only the API refused them. `environment:` wins over
    env_file, so every service but the two that need one of them holds
    both as empty strings, which every reader counts as unset."""
    readers_of_the_owner = {"postgres", "migrate"}
    assert readers_of_the_owner < set(services)
    for name, svc in services.items():
        if name in readers_of_the_owner:
            continue
        env = svc.get("environment") or {}
        assert env.get(config.OWNER_PASSWORD_ENV) == "", name
        assert env.get(config.MIGRATION_DSN_ENV) == "", name
    # The two that keep them: postgres takes the password at initdb, the
    # migrate job the DSN, and neither blanks what it needs.
    assert config.OWNER_PASSWORD_ENV not in (services["postgres"].get("environment") or {})
    assert config.MIGRATION_DSN_ENV not in (services["migrate"].get("environment") or {})


def test_the_owner_variables_are_blanked_where_a_secrets_file_reaches():
    """The services above are every service compose runs: a new one that
    reads secrets.env without the anchor fails the test above, and the
    anchor is one declaration, not eleven copies."""
    text = (PROD / "compose.yml").read_text(encoding="utf-8")
    anchor = text[text.index("x-no-owner-credential: &no-owner-credential\n"):]
    anchor = anchor[:anchor.index("\n\n")]
    assert anchor.splitlines()[1:] == ['  POSTGRES_PASSWORD: ""',
                                       '  NOCTORNAL_MIGRATION_DATABASE_URL: ""']
    assert text.count("<<: *no-owner-credential") == 11


def test_the_templates_put_each_owner_variable_where_it_lives():
    secrets = _assignments(PROD / "secrets.env.example")
    init = _assignments(PROD / "postgres-init.env.example")
    migrate = _assignments(PROD / "migrate.env.example")
    for name in (config.OWNER_PASSWORD_ENV, config.MIGRATION_DSN_ENV):
        assert name not in secrets, name
    assert config.OWNER_PASSWORD_ENV in init
    assert set(migrate) == {config.MIGRATION_DSN_ENV}
    # And the template's two halves agree, as the files they become must.
    from urllib.parse import urlsplit
    assert urlsplit(migrate[config.MIGRATION_DSN_ENV]).password == init[config.OWNER_PASSWORD_ENV]
    assert urlsplit(migrate[config.MIGRATION_DSN_ENV]).username == "noctornal"


def test_the_templates_placeholders_are_refused_where_they_are_read():
    init = _assignments(PROD / "postgres-init.env.example")
    migrate = _assignments(PROD / "migrate.env.example")
    env = {"NOCTORNAL_ENV": "production", **migrate}
    assert any("placeholder" in p for p in config.migration_job_problems(env))
    runtime = _production()
    runtime[config.OWNER_PASSWORD_ENV] = init[config.OWNER_PASSWORD_ENV]
    _only(config.verify_environment(runtime), config.OWNER_PASSWORD_ENV)


def test_the_secrets_files_and_their_backups_are_ignored_by_git():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "infra/production/migrate.env\n" in ignored
    assert "infra/production/*.env.backup-*\n" in ignored
    assert (PROD / "migrate.env.example").is_file()


def _gitignored(path: str) -> bool:
    """git's rule for the patterns this file uses: a `!` line re-includes,
    and the last match wins."""
    verdict = False
    for raw in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        pattern = (line[1:] if negate else line).rstrip("/")
        if fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, pattern + "/*"):
            verdict = not negate
    return verdict


@pytest.mark.parametrize("name", [
    "secrets.env", "postgres-init.env", "migrate.env",
    "secrets.env.backup-20261002T120000Z",
    # The helper's temporary file, which holds a whole new secrets file for
    # the instant before the rename and survives a kill or a power cut
    # (g32 verify of 2026-10-03: it was ignored by nothing).
    ".secrets.env.tmp-4242", ".postgres-init.env.tmp-17", ".migrate.env.tmp-9",
])
def test_the_helpers_files_and_its_temporaries_are_ignored_by_git(name):
    assert _gitignored(f"infra/production/{name}"), name


def test_the_gitignore_reader_is_not_vacuous():
    assert not _gitignored("infra/production/compose.yml")
    assert not _gitignored("infra/production/secrets.env.example")
    assert not _gitignored("scripts/production_secrets.py")
    assert _gitignored("infra/production/tls/private.key")


def test_no_upgrade_note_copies_a_template_over_an_existing_postgres_init_env():
    """Since F52 postgres-init.env holds the schema owner's password, so a
    note that copies its template unconditionally puts a placeholder over
    it for an operator who has already run the secrets step (g32 verify of
    2026-10-03: release/egress-upgrade/README.md still did)."""
    notes = [*ROOT.glob("*.md"), *(ROOT / "release").rglob("*.md"),
             *(ROOT / "infra").rglob("*.md"), *(ROOT / "docs").glob("*.md")]
    assert any(n.name == "README.md" and n.parent.name == "egress-upgrade" for n in notes)
    for note in notes:
        for number, line in enumerate(note.read_text(encoding="utf-8").splitlines(), 1):
            if "cp " in line and "postgres-init.env.example" in line:
                assert re.match(r"^\[ -[ef] \S*postgres-init\.env \] \|\| cp ", line), \
                    f"{note.relative_to(ROOT)}:{number}: {line}"


def _dockerignored(path: str) -> bool:
    """Docker's rule for these patterns: the last matching line wins, and a
    `!` line re-includes."""
    verdict = False
    for raw in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        pattern = line[1:] if negate else line
        if fnmatch.fnmatchcase(path, pattern.rstrip("/")) or \
                fnmatch.fnmatchcase(path, pattern.rstrip("/") + "/*"):
            verdict = not negate
    return verdict


@pytest.mark.parametrize("name", [
    "secrets.env", "postgres-init.env", "migrate.env", "egress-proxy.env",
    "egress-client.env", "secrets.env.backup-20261002T120000Z",
    "migrate.env.backup-20261002T120000Z-2", ".secrets.env.tmp-4242",
])
def test_no_secrets_file_or_backup_reaches_the_image(name):
    """Until F52 only secrets.env was excluded, so postgres-init.env and the
    egress files were baked into the image every runtime container runs,
    and migrate.env would have been: the owner's DSN on the API's own disk."""
    assert _dockerignored(f"infra/production/{name}"), name


def test_the_dockerignore_reader_is_not_vacuous():
    assert not _dockerignored("infra/production/compose.yml")
    assert not _dockerignored("apps/api/src/noctornal_api/config.py")
    assert _dockerignored(".env.local")


# ---------------------------------------------------------------------------
# The runtime refusal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name, value, home", [
    (config.OWNER_PASSWORD_ENV, OWNER_PASSWORD, "postgres-init.env"),
    (config.MIGRATION_DSN_ENV, OWNER_DSN, "migrate.env"),
])
def test_a_runtime_process_holding_the_owner_credential_is_refused(name, value, home):
    env = _production()
    env[name] = value
    problem = _only(config.verify_environment(env), name)
    assert home in problem and "--production-secrets" in problem
    assert "row-level security" in problem and "append-only" in problem
    assert OWNER_PASSWORD not in problem


def test_both_are_refused_one_sentence_each():
    env = _production()
    env[config.OWNER_PASSWORD_ENV] = OWNER_PASSWORD
    env[config.MIGRATION_DSN_ENV] = OWNER_DSN
    problems = config.verify_environment(env)
    assert len(problems) == 2, problems
    assert OWNER_PASSWORD not in "\n".join(problems)


def test_an_empty_value_is_unset():
    env = _production()
    env[config.OWNER_PASSWORD_ENV] = "  "
    env[config.MIGRATION_DSN_ENV] = ""
    assert config.verify_environment(env) == []


def test_a_published_owner_password_is_refused_once():
    """One variable, one refusal: the published value is the sentence."""
    env = _production()
    env[config.OWNER_PASSWORD_ENV] = "replace-me-owner-password"
    problem = _only(config.verify_environment(env), config.OWNER_PASSWORD_ENV)
    assert "placeholder" in problem


def test_the_egress_proxy_refuses_both_halves_of_the_owner_credential():
    """The proxy reads egress-proxy.env alone and already refused the
    owner's DSN; its password is refused beside it."""
    from noctornal_api import egress_proxy
    from test_egress_refusals import _proxy_env
    for name in (config.OWNER_PASSWORD_ENV, config.MIGRATION_DSN_ENV):
        assert name in egress_proxy.FORBIDDEN_ENV
        problems = egress_proxy.verify_proxy_environment(_proxy_env(**{name: OWNER_PASSWORD}))
        assert any(name in p for p in problems), problems


def test_the_rule_is_production_only_at_boot_and_mode_blind_as_a_reader():
    env = _production()
    env["NOCTORNAL_ENV"] = "development"
    env[config.OWNER_PASSWORD_ENV] = OWNER_PASSWORD
    assert config.verify_environment(env) == []
    assert len(config.owner_credential_problems(env)) == 1


# ---------------------------------------------------------------------------
# The migration job
# ---------------------------------------------------------------------------

def _job():
    spec = importlib.util.spec_from_file_location("migrate_job", ROOT / "scripts" / "migrate_job.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_job_without_its_dsn_refuses_naming_the_installer_step():
    problems = config.migration_job_problems({"NOCTORNAL_ENV": "production"})
    assert len(problems) == 1
    assert "migrate.env" in problems[0] and "--production-secrets" in problems[0]
    assert "-ProductionSecrets" in problems[0]


@pytest.mark.parametrize("dsn", [
    "postgresql+psycopg://noctornal:replace-me-owner-password@postgres:5432/noctornal",
    f"postgresql+psycopg://noctornal:{config.DEV_CREDENTIAL}@postgres:5432/noctornal",
])
def test_the_job_refuses_a_published_owner_password(dsn):
    problems = config.migration_job_problems({"NOCTORNAL_ENV": "production",
                                              config.MIGRATION_DSN_ENV: dsn})
    assert len(problems) == 1 and config.MIGRATION_DSN_ENV in problems[0]


def test_the_job_refuses_a_dsn_that_names_no_role():
    problems = config.migration_job_problems({"NOCTORNAL_ENV": "production",
                                              config.MIGRATION_DSN_ENV: "postgresql://postgres/n"})
    assert problems and "names no role" in problems[0]


def test_the_job_rules_are_production_only():
    assert config.migration_job_problems({}) == []


def test_the_job_refuses_with_exit_1_and_no_value():
    err = io.StringIO()
    calls = []
    status = _job().main({"NOCTORNAL_ENV": "production",
                          config.MIGRATION_DSN_ENV: "postgresql+psycopg://noctornal:"
                          "Zx9-replace-me@postgres:5432/noctornal"},
                         execvpe=lambda *a: calls.append(a), err=err)
    assert status == 1 and calls == []
    assert err.getvalue().startswith("migrate: ")
    assert "Zx9" not in err.getvalue()


def test_the_job_without_a_dsn_outside_production_still_refuses():
    err = io.StringIO()
    status = _job().main({}, execvpe=lambda *a: pytest.fail("ran alembic"), err=err)
    assert status == 1 and config.MIGRATION_DSN_ENV in err.getvalue()


def test_the_job_runs_alembic_as_the_owner():
    calls = []
    env = {"NOCTORNAL_ENV": "production", config.MIGRATION_DSN_ENV: f" {OWNER_DSN} ",
           "DATABASE_URL": "postgresql+psycopg://noctornal_app:x@postgres/noctornal"}
    status = _job().main(env, execvpe=lambda *a: calls.append(a), err=io.StringIO())
    assert status == 0
    (program, argv, child), = calls
    assert program == "alembic" and argv == ["alembic", "upgrade", "head"]
    assert child["DATABASE_URL"] == OWNER_DSN
