"""Every credential value this repository publishes, refused in production
and reported by the readiness register (sec-dev-secrets-in-production,
2026-09-23).

Until that date the boot check knew one published value,
`dev_only_change_me`. The repository publishes more: the placeholders in
infra/production/secrets.env.example, the throwaway pepper the suites and
the demo seeders set, the KEK printed in the CI workflow (and the one
conftest sets), the development Redis URL that carries no password at all,
and MinIO's own `minioadmin`. A production deployment carrying any of them
started cleanly.

Two halves are held here:

* the rules, one at a time against a dictionary, as test_config_boot.py
  does (its `_production()` is imported so the two files cannot disagree
  about what a good environment is);
* the REPOSITORY. `test_every_credential_the_repository_publishes_is_
  refused` reads the files that publish credentials (the CI workflow, both
  compose files' development half, the production template, the installers,
  the launchers, and every `os.environ.setdefault` in the suites and
  scripts) and fails if any credential literal in them would start a
  production API. That is what makes the marker list in config.py a list of
  what the repository publishes rather than of what somebody remembered.

Pure: no database, no Redis.
"""
from __future__ import annotations

import ast
import base64
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from noctornal_api import config, readiness
from test_config_boot import _only, _production

ROOT = Path(__file__).resolve().parents[3]


def _refused(env: dict[str, str]) -> list[str]:
    return config.verify_environment(env)


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------

_SECRETS = ("DATABASE_URL", "REDIS_URL", "MINIO_SECRET_KEY", "SAMPLE_SECRET_KEY",
            "PRESERVE_SECRET_KEY", "POSTGRES_PASSWORD", "SMTP_PASSWORD",
            "NOCTORNAL_INGEST_PEPPER", "NOCTORNAL_WEBHOOK_SECRET")


@pytest.mark.parametrize("variable", _SECRETS)
@pytest.mark.parametrize("value", [
    "replace-me-redis-password",
    "prefix-REPLACE-ME-suffix",
    "test-pepper-not-a-real-one",
    "dev-only-ingest-pepper-not-a-real-one",
])
def test_every_published_marker_is_refused_wherever_it_is_set(variable, value):
    env = _production()
    if variable.endswith("_URL"):
        value = f"redis://:{value}@redis:6379/0" if variable == "REDIS_URL" \
            else f"postgresql+psycopg://noctornal_app:{value}@db:5432/noctornal"
    env[variable] = value
    problem = _only(_refused(env), variable)
    assert problem.endswith("."), problem


def test_a_refusal_names_the_marker_and_never_the_secret_around_it():
    env = _production()
    env["DATABASE_URL"] = "postgresql+psycopg://noctornal_app:Hq7-replace-me-Zt4@db:5432/n"
    problem = _only(_refused(env), "DATABASE_URL")
    assert "secrets.env.example" in problem
    assert "Hq7" not in problem and "Zt4" not in problem


@pytest.mark.parametrize("variable", ["MINIO_SECRET_KEY", "MINIO_ROOT_PASSWORD",
                                      "SAMPLE_SECRET_KEY"])
@pytest.mark.parametrize("value", ["minioadmin", " MinioAdmin "])
def test_minios_own_default_is_refused(variable, value):
    env = _production()
    env[variable] = value
    problem = _only(_refused(env), variable)
    # MinIO's documentation publishes it, not this repository's source,
    # and the refusal says so rather than borrowing the markers' sentence.
    assert "read MinIO's documentation already holds" in problem, problem


def test_minios_default_inside_a_longer_secret_is_not_its_default():
    """Matched as the whole value: a generated secret that happens to
    contain the word is not the credential MinIO starts on."""
    env = _production()
    env["MINIO_SECRET_KEY"] = "Qp7-minioadmin-xL2vD9"
    assert _refused(env) == []


# The identity half of a pair (review of sec-dev-secrets-in-production,
# 2026-09-23). `_KEY` marks an access key as a credential, and the first cut
# refused `MINIO_ACCESS_KEY=minioadmin` beside a strong secret, telling the
# operator "anyone who has read the source already holds this deployment's
# secret". The access key is the account NAME; the sentence was false and
# the refusal would have taught somebody to unset NOCTORNAL_ENV.

_IDENTITIES = ("MINIO_ACCESS_KEY", "SAMPLE_ACCESS_KEY", "PRESERVE_ACCESS_KEY",
               "NOCTORNAL_TOTP_KEK_ID")


@pytest.mark.parametrize("variable", _IDENTITIES)
@pytest.mark.parametrize("value", ["minioadmin", "noctornal",
                                   "replace-me-minio-root-user",
                                   config.DEV_CREDENTIAL])
def test_a_published_identity_beside_a_strong_secret_starts(variable, value):
    env = _production()
    env[variable] = value
    # Only this rule's sentence is asked about: the key ring has rules of
    # its own for what a KEK id may look like, and they are not this one.
    problems = [p for p in _refused(env) if "already holds" in p]
    assert problems == [], problems
    assert variable not in {p.variable for p in config.published_credentials(env)}
    if variable != "NOCTORNAL_TOTP_KEK_ID":
        assert _refused(env) == []


def test_minios_default_in_both_halves_is_refused_once_on_the_secret():
    """The deployment MinIO's own warning is about. The secret is what
    makes it published, so that is the variable the refusal names; the
    access key beside it adds nothing an operator has to read twice."""
    env = _production()
    env["MINIO_ACCESS_KEY"] = "minioadmin"
    env["MINIO_SECRET_KEY"] = "minioadmin"
    problems = _refused(env)
    assert len(problems) == 1, problems
    assert problems[0].startswith("MINIO_SECRET_KEY "), problems


@pytest.mark.parametrize("variable", ["AWS_SECRET_ACCESS_KEY", "SMTP_PASSWORD_USER",
                                      "BACKUP_SECRET_ID"])
def test_a_secret_word_wins_over_an_identity_suffix(variable):
    """`AWS_SECRET_ACCESS_KEY` ends like an access key and IS the secret.
    Exempting it by its suffix would reopen the hole this module closes."""
    assert not config._names_identity(variable)
    env = _production()
    env[variable] = "minioadmin"
    assert "MinIO" in _only(_refused(env), variable)


@pytest.mark.parametrize("variable, identity", [
    ("MINIO_ACCESS_KEY", True), ("minio_access_key", True),
    ("SAMPLE_ACCESS_KEY", True), ("NOCTORNAL_TOTP_KEK_ID", True),
    ("DB_USER", True), ("SMTP_USERNAME", True), ("APP_DB_ROLE", True),
    ("MINIO_SECRET_KEY", False), ("NOCTORNAL_TOTP_KEK", False),
    ("DATABASE_URL", False), ("NOCTORNAL_INGEST_PEPPER", False),
    ("MINIO_ACCESS_KEY_SUFFIXED", False),
])
def test_what_counts_as_an_identity(variable, identity):
    assert config._names_identity(variable) is identity


def test_the_row_does_not_list_an_identity(clean_environment):
    clean_environment.setenv("MINIO_ACCESS_KEY", "minioadmin")
    clean_environment.setenv("MINIO_SECRET_KEY", "Qp7xL2vD9strongsecret")
    check = readiness._credentials_not_published(None)
    assert check.ok is True, check


#: CI's KEK (base64 of 32 'A' bytes), conftest's ("A" * 43 + "=", 32 zero
#: bytes), and any other single repeated byte.
_REPEATED_KEKS = (
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
    "A" * 43 + "=",
    base64.b64encode(b"k" * 32).decode(),
    base64.b64encode(b"k" * 32).decode() + "\n",
)


@pytest.mark.parametrize("kek", _REPEATED_KEKS)
def test_a_key_of_one_repeated_byte_is_refused_once(kek):
    env = _production()
    env["NOCTORNAL_TOTP_KEK"] = kek
    problem = _only(_refused(env), "NOCTORNAL_TOTP_KEK")
    assert "repeated" in problem
    assert kek.strip() not in problem


def test_the_templates_kek_placeholder_is_one_refusal_not_two():
    """`replace-me-base64-32-bytes` is a placeholder AND an unusable key.
    One variable, one refusal, and the placeholder is the useful one."""
    env = _production()
    env["NOCTORNAL_TOTP_KEK"] = "replace-me-base64-32-bytes"
    assert "placeholder" in _only(_refused(env), "NOCTORNAL_TOTP_KEK")


@pytest.mark.parametrize("url", [
    "redis://127.0.0.1:6379/0",
    "redis://localhost:6379/0",
    "redis://redis:6379/0",
    "redis://limiter@redis:6379/0",
    "redis://:@redis:6379/0",
    "REDIS://redis:6379/0",
    # A blank query password sets nothing in redis-py either (c23,
    # 2026-09-24), and a differently cased name is passed on as an
    # unknown keyword rather than as the password.
    "redis://redis:6379/0?password=",
    "redis://redis:6379/0?PASSWORD=Zm4tRq",
])
def test_a_redis_url_with_no_password_is_refused(url):
    env = _production()
    env["REDIS_URL"] = url
    problem = _only(_refused(env), "REDIS_URL")
    assert "no password" in problem


@pytest.mark.parametrize("url", [
    "rediss://redis.example.gov:6380/0",
    "unix:///run/redis/limiter.sock",
    "redis://limiter:Zm4tR@redis:6379/0",
    # c23 (2026-09-24): redis-py's `parse_url` hands a `password` query
    # argument to the connection just as it does the userinfo one, and
    # this was refused at boot as "asks for no password".
    "redis://redis:6379/0?password=Zm4tRq",
    "redis://redis:6379/1?socket_timeout=2&password=Zm4tRq",
])
def test_redis_authenticated_another_way_is_accepted(url):
    """A client certificate and a socket's permissions both authenticate
    without a password in the URL. Refusing them would stop a correctly
    secured deployment for looking unlike the compose file."""
    env = _production()
    env["REDIS_URL"] = url
    assert _refused(env) == []


@pytest.mark.parametrize("url", [
    "redis://redis:6379/0?password=Zm4tRq",
    "redis://redis:6379/1?socket_timeout=2&password=Zm4tRq",
    "redis://redis:6379/0?password=Zm4tRq#limiter",
    "redis://limiter:Zm4tRq@redis:6379/0",
])
def test_the_password_the_check_accepts_is_the_one_the_client_uses(url):
    """The acceptance above is only true if redis-py really authenticates
    with the password in each shape, so it is asked rather than assumed;
    and the evidence and log line that print the URL must print none of
    it (c23, 2026-09-24)."""
    connection = pytest.importorskip("redis.connection")
    from noctornal_api.http.limits import redacted_url

    assert connection.parse_url(url).get("password") == "Zm4tRq"
    assert "Zm4tRq" not in redacted_url(url), redacted_url(url)
    assert "redis:6379" in redacted_url(url), (
        "the redaction took the host with it, and the host is what the "
        "evidence is for")


@pytest.mark.parametrize("variable", config._DECLARATIONS)
def test_the_templates_declaration_placeholders_are_refused(variable):
    """`samples.policy_declared` accepts any non-empty string, so the
    template's `replace-me-policy-reference` declared a policy nobody wrote
    and turned the blocking L1 row green."""
    env = _production()
    env[variable] = f"replace-me-{variable.lower()}"
    assert "docs/16 L1" in _only(_refused(env), variable)


def test_a_real_declaration_is_accepted():
    env = _production()
    env["NOCTORNAL_PROHIBITED_CONTENT_POLICY"] = "POL-2026-014"
    env["NOCTORNAL_DESIGNATED_PERSON"] = "Duty legal adviser"
    assert _refused(env) == []


def test_the_rules_are_production_only_at_boot():
    env = _production()
    env["NOCTORNAL_ENV"] = "development"
    env["REDIS_URL"] = "redis://127.0.0.1:6379/0"
    env["NOCTORNAL_TOTP_KEK"] = "A" * 43 + "="
    assert _refused(env) == []
    # ...while the reader itself is mode-blind, which is what lets the
    # readiness register report a misspelt production.
    assert {p.variable for p in config.published_credentials(env)} == {
        "REDIS_URL", "NOCTORNAL_TOTP_KEK"}


def test_the_process_environment_is_put_back():
    before = dict(os.environ)
    config.published_credentials({"NOCTORNAL_TOTP_KEK": "A" * 43 + "="})
    assert dict(os.environ) == before


# ---------------------------------------------------------------------------
# The repository: every credential it publishes must be refused
# ---------------------------------------------------------------------------

#: The files that set credentials for a process to run with. Development
#: and CI files are listed because their values are exactly the ones a
#: hurried production copies.
_TEXT_SOURCES = (
    ".github/workflows/ci.yml",
    "infra/docker-compose.yml",
    "infra/production/secrets.env.example",
    "release/install.sh",
    "release/install.ps1",
    "scripts/launch.sh",
    "scripts/launch.ps1",
)
_PY_SOURCES = ("apps/api/tests", "scripts")


_ASSIGNMENTS = (
    re.compile(r"(?<![A-Za-z0-9_$])([A-Z][A-Z0-9_]{2,})=([^\s'\"`;]+)"),     # NAME=value
    re.compile(r"^\s*([A-Z][A-Z0-9_]{2,}):\s+\"?([^\s\"#]+)\"?\s*$"),        # NAME: value
    re.compile(r"\b([A-Z][A-Z0-9_]{2,})\s+=\s+'([^']*)'"),                   # NAME = 'v'
    re.compile(r"set_default\s+([A-Z][A-Z0-9_]*)\s+'([^']*)'"),              # launch.sh
    # `export NAME="${NAME:-v}"`, the default an installer exports. Only
    # that shape: `${KEK_BYTES:-0}` in a message is a shell variable.
    re.compile(r"export\s+([A-Z][A-Z0-9_]*)=\"\$\{\1:-([^}]*)\}\""),
)


def _text_assignments(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        for pattern in _ASSIGNMENTS:
            for name, value in pattern.findall(line):
                yield name, value


def _constant(node: ast.AST):
    """The value of a string expression built from constants alone
    (`"A" * 43 + "="`), or None for anything that reads a name."""
    if not all(isinstance(n, (ast.Constant, ast.BinOp, ast.Add, ast.Mult))
               for n in ast.walk(node)):
        return None
    # Every node was checked above to be a constant or an operator on them.
    value = eval(compile(ast.Expression(node), "<constant>", "eval"),
                 {"__builtins__": {}})
    return value if isinstance(value, str) else None


def _py_assignments(path: Path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "setdefault"
                and ast.unparse(node.func.value) in ("os.environ", "environ")
                and len(node.args) == 2
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            value = _constant(node.args[1])
            if value is not None:
                yield node.args[0].value, value


def _is_credential_literal(name: str, value: str) -> bool:
    # Variables that carry an IDENTITY rather than a secret (`noctornal` as
    # an access key) are classified by config's own function, so the scan
    # and the runtime rule cannot disagree about which half of a pair is the
    # secret, which is what they did before the 2026-09-23 review.
    if not config._carries_credential(name) or config._names_identity(name):
        return False
    if not value or "$" in value or "%" in value or value.startswith("<"):
        return False
    if name.endswith(("_URL", "_DSN")):
        parts = urlsplit(value)
        return bool(parts.password) or parts.scheme.lower() == "redis"
    return True


def _published() -> set[tuple[str, str, str]]:
    found = set()
    for rel in _TEXT_SOURCES:
        path = ROOT / rel
        for name, value in _text_assignments(path):
            if _is_credential_literal(name, value):
                found.add((path.name, name, value))
    for rel in _PY_SOURCES:
        for path in sorted((ROOT / rel).rglob("*.py")):
            for name, value in _py_assignments(path):
                if _is_credential_literal(name, value):
                    found.add((path.name, name, value))
    return found


#: The vacuity guard. A scan that silently stopped matching anything would
#: pass the test below by finding nothing to check.
_MUST_FIND = {
    ("ci.yml", "DATABASE_URL"), ("ci.yml", "REDIS_URL"),
    ("ci.yml", "NOCTORNAL_TOTP_KEK"), ("ci.yml", "MINIO_SECRET_KEY"),
    ("ci.yml", "PGPASSWORD"), ("ci.yml", "MINIO_ROOT_PASSWORD"),
    ("docker-compose.yml", "POSTGRES_PASSWORD"),
    ("docker-compose.yml", "MINIO_ROOT_PASSWORD"),
    ("secrets.env.example", "DATABASE_URL"), ("secrets.env.example", "REDIS_URL"),
    ("secrets.env.example", "NOCTORNAL_TOTP_KEK"),
    ("secrets.env.example", "NOCTORNAL_INGEST_PEPPER"),
    ("secrets.env.example", "PRESERVE_SECRET_KEY"),
    ("secrets.env.example", "SMTP_PASSWORD"),
    ("install.sh", "REDIS_URL"), ("install.sh", "MINIO_SECRET_KEY"),
    ("install.ps1", "DATABASE_URL"), ("install.ps1", "REDIS_URL"),
    ("launch.sh", "DATABASE_URL"), ("launch.ps1", "REDIS_URL"),
    ("conftest.py", "NOCTORNAL_TOTP_KEK"),
    ("test_ingest_pg.py", "NOCTORNAL_INGEST_PEPPER"),
    ("seed_feeds_demo.py", "NOCTORNAL_INGEST_PEPPER"),
}


def test_the_scan_finds_what_the_repository_publishes():
    found = {(where, name) for where, name, _value in _published()}
    missing = _MUST_FIND - found
    assert not missing, f"the scan no longer sees {sorted(missing)}"


def test_every_credential_the_repository_publishes_is_refused():
    """The guard on the marker list. A new service in the dev compose file,
    a new CI secret or a new test pepper is either refused here or this
    fails, naming the file and the variable (never the value)."""
    started = []
    for where, name, value in sorted(_published()):
        env = _production()
        env[name] = value
        if not any(name in problem for problem in _refused(env)):
            started.append(f"{where}: {name}")
    assert not started, (
        "a production API would start on these published credentials: "
        + ", ".join(started))


def test_the_production_templates_declarations_are_refused():
    template = ROOT / "infra" / "production" / "secrets.env.example"
    values = dict(_text_assignments(template))
    for name in config._DECLARATIONS:
        env = _production()
        env[name] = values[name]
        _only(_refused(env), name)


# ---------------------------------------------------------------------------
# The readiness row
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_environment(monkeypatch):
    """This process's environment with every credential taken out, so a
    test states exactly which ones are present. The suite's own conftest
    KEK is one of the things removed: it is a published key."""
    for name in list(os.environ):
        if config._carries_credential(name):
            monkeypatch.delenv(name)
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    return monkeypatch


def test_the_row_passes_when_nothing_published_is_held(clean_environment):
    clean_environment.setenv("DATABASE_URL", "postgresql+psycopg://a:Xk9pQ@db/n")
    clean_environment.setenv("REDIS_URL", "redis://:Zm4tR@redis:6379/0")
    check = readiness._credentials_not_published(None)
    assert check.ok is True, check
    assert check.action == ""
    assert "not visible from here" in check.evidence


def test_the_row_names_every_variable_and_never_a_value(clean_environment):
    clean_environment.setenv(
        "DATABASE_URL", f"postgresql+psycopg://a:Hq7{config.DEV_CREDENTIAL}@db/n")
    clean_environment.setenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    clean_environment.setenv("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
    clean_environment.setenv("SMTP_PASSWORD", "replace-me-smtp-password")
    check = readiness._credentials_not_published(None)
    assert check.ok is False
    assert check.evidence.startswith("4 credentials carry a value"), check.evidence
    for name in ("DATABASE_URL", "REDIS_URL", "NOCTORNAL_TOTP_KEK", "SMTP_PASSWORD"):
        assert name in check.evidence, name
    for secret in ("Hq7", "A" * 43, "127.0.0.1", "smtp-password"):
        assert secret not in check.evidence + check.action, secret
    assert "did not run" in check.evidence, "development must say the boot check was off"
    assert "refuses to start" in check.action


def test_the_row_counts_one_in_agreement(clean_environment):
    clean_environment.setenv("REDIS_URL", "redis://redis:6379/0")
    check = readiness._credentials_not_published(None)
    assert check.evidence.startswith("1 credential carries a value"), check.evidence


def test_the_row_says_a_production_process_should_not_have_started(clean_environment):
    clean_environment.setenv("NOCTORNAL_ENV", "production")
    clean_environment.setenv("MINIO_SECRET_KEY", "minioadmin")
    check = readiness._credentials_not_published(None)
    assert check.ok is False
    assert "should not have started" in check.evidence


def test_the_row_is_registered_and_does_not_block():
    """Red on every development machine and in CI by design, so it must
    never be the thing that refuses a collection poll there."""
    assert "credentials_not_published" in readiness.CHECK_NAMES
    assert "credentials_not_published" not in readiness.BLOCKING_CHECKS
