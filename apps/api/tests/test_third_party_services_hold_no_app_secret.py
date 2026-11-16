"""Postgres, Redis and MinIO hold no secret of the application's (the independent review TRANSPORT-01, docs/17 2026-11-15).

infra/production/compose.yml gave secrets.env to postgres, redis, minio and minio-init, so each of those
processes held the TOTP key ring, both peppers, the mail stamp key and the system role's DSN, which
none of them reads. They run another project's image, start as root and check nothing, so a party who
ran code in one of them read every key. Held here, on the compose file, the templates and the installer
step, with no Docker:

* none of the four reads secrets.env: postgres reads postgres-init.env, redis reads redis.env, and
  minio and minio-init read minio.env, each optional, and nothing else reads those two;
* every secret an env template names is blank in each one's `environment:` but what that one reads,
  and nothing it reads is blanked, so a line pasted into its own file reaches nothing;
* the installer step writes into redis.env and minio.env what those services read, and the database's
  last secrets.env line, NOCTORNAL_APP_DB_PASSWORD, now lives in postgres-init.env;
* without its file Redis refuses an empty password, and MinIO and minio-init refuse an empty root pair
  rather than start on MinIO's published default, each naming the installer step.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import textwrap
from pathlib import Path

import pytest
from acl_redis_support import posix_shell, run_start_script
from test_egress_topology import Reader, _env_files

ROOT = Path(__file__).resolve().parents[3]
PROD = ROOT / "infra" / "production"

#: What each service reads, and the file it reads it from.
READS = {
    "postgres": ("postgres-init.env", {"POSTGRES_PASSWORD", "NOCTORNAL_APP_DB_PASSWORD",
                                       "NOCTORNAL_WORKER_DB_PASSWORD",
                                       "NOCTORNAL_EGRESS_DB_PASSWORD"}),
    "redis": ("redis.env", {"REDIS_PASSWORD", "REDIS_URL"}),
    "minio": ("minio.env", {"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"}),
    "minio-init": ("minio.env", {"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD", "SAMPLE_ACCESS_KEY",
                                 "SAMPLE_SECRET_KEY", "PRESERVE_ACCESS_KEY",
                                 "PRESERVE_SECRET_KEY"}),
}
#: A name is a secret when it carries a password, a key, a pepper, a token or a DSN; an id, a
#: public half or a ceiling is not.
_SECRET = re.compile(r"PASSWORD|SECRET|PEPPER|TOKEN|_KEK|_KEY\b|_KEY_RETIRED|DATABASE_URL$|"
                     r"^REDIS_URL$|ROOT_USER|ACCESS_KEY")
_ASSIGNED = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=", re.M)
#: The store administrator's pair, read from object-store-admin.env, which has no template.
_ADMIN = {"OBJECT_STORE_ADMIN_ACCESS_KEY", "OBJECT_STORE_ADMIN_SECRET_KEY"}


@pytest.fixture(scope="module")
def services():
    return Reader((PROD / "compose.yml").read_text(encoding="utf-8")).document()["services"]


def _secrets() -> set[str]:
    names = set(_ADMIN)
    for template in PROD.glob("*.env.example"):
        names |= {n for n in _ASSIGNED.findall(template.read_text(encoding="utf-8"))
                  if _SECRET.search(n) and not n.endswith("_ID")}
    return names


def _helper():
    spec = importlib.util.spec_from_file_location("production_secrets",
                                                  ROOT / "scripts" / "production_secrets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_secret_reader_is_not_vacuous():
    found = _secrets()
    for name in ("NOCTORNAL_TOTP_KEK", "NOCTORNAL_TOTP_KEK_RETIRED", "NOCTORNAL_AUDIT_PEPPER",
                 "NOCTORNAL_INGEST_PEPPER", "NOCTORNAL_MAIL_STAMP_KEY", "DATABASE_URL",
                 "NOCTORNAL_WORKER_DATABASE_URL", "NOCTORNAL_MIGRATION_DATABASE_URL",
                 "NOCTORNAL_PERSONA_KEK", "NOCTORNAL_EGRESS_SEAL_KEY", "SMTP_PASSWORD",
                 "NOCTORNAL_WEBHOOK_SECRET", "NOCTORNAL_SANDBOX_TOKEN", "REDIS_PASSWORD",
                 "MINIO_ROOT_PASSWORD", "SAMPLE_SECRET_KEY", "POSTGRES_PASSWORD"):
        assert name in found, name
    for name in ("NOCTORNAL_TOTP_KEK_ID", "NOCTORNAL_EGRESS_SEAL_PUBLIC", "MINIO_ENDPOINT"):
        assert name not in found, name


def test_postgres_redis_and_minio_read_no_secrets_env(services):
    for name, (own, _reads) in READS.items():
        assert _env_files(services[name]) == [(own, False)], name


def test_only_they_read_their_own_files(services):
    for own, readers in (("redis.env", {"redis"}), ("minio.env", {"minio", "minio-init"}),
                         ("postgres-init.env", {"postgres"})):
        assert {n for n, svc in services.items() if own in dict(_env_files(svc))} == readers, own


@pytest.mark.parametrize("name", sorted(READS))
def test_every_secret_but_its_own_is_blank_on_it(services, name):
    """A line pasted into its own file, or a secret a later template adds, reaches nothing: the test
    reads the secrets from the templates, so a new one fails here until it is blanked."""
    environment = services[name].get("environment") or {}
    _own_file, reads = READS[name]
    for secret in sorted(_secrets() - reads):
        assert environment.get(secret) == "", f"{name} does not blank {secret}"
    for secret in reads:
        assert secret not in environment, f"{name} blanks {secret}, which it reads"


def test_the_installer_writes_what_each_reads():
    helper = _helper()
    assert set(helper.DERIVED[helper.REDIS]) == READS["redis"][1]
    assert READS["minio-init"][1] <= set(helper.DERIVED[helper.STORE])
    assert not set(helper.MINIO_CLIENT) & set(helper.DERIVED[helper.STORE])
    for bucket in ("EVIDENCE_BUCKET", "INGEST_BUCKET", "SAMPLE_BUCKET", "COLLECT_RAW_BUCKET",
                   "PRESERVE_BUCKET"):
        assert bucket in helper.DERIVED[helper.STORE], bucket
    init = PROD / "postgres-init.env.example"
    assert set(_ASSIGNED.findall(init.read_text(encoding="utf-8"))) == READS["postgres"][1]
    secrets = (PROD / "secrets.env.example").read_text(encoding="utf-8")
    assert not re.search(r"(?m)^NOCTORNAL_APP_DB_PASSWORD=", secrets)
    assert ("NOCTORNAL_APP_DB_PASSWORD", helper.POSTGRES_INIT) in [m[:2] for m in helper.MOVES]


def _script(services, name: str) -> str:
    entry = services[name]["entrypoint"]
    assert entry[:2] == ["/bin/sh", "-c"], name
    return textwrap.dedent(entry[2]).replace("$$", "$")


needs_sh = pytest.mark.skipif(posix_shell() is None, reason="no POSIX sh on this machine")


def _run(script: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([posix_shell(), "-c", script], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", **env}, timeout=60)


@needs_sh
@pytest.mark.parametrize("pair", [{}, {"MINIO_ROOT_USER": "root-user"},
                                  {"MINIO_ROOT_PASSWORD": "root-password-1"}])
def test_minio_refuses_an_empty_root_pair_rather_than_start_on_its_default(services, pair):
    script = _script(services, "minio").replace("exec minio server", "exec echo minio server")
    run = _run(script, pair)
    assert run.returncode == 1 and run.stdout == ""
    assert run.stderr.startswith("MINIO_ROOT_USER or MINIO_ROOT_PASSWORD is empty: refusing")
    assert "minio.env" in run.stderr and "release/install.sh --production-secrets" in run.stderr
    started = _run(script, {"MINIO_ROOT_USER": "root-user", "MINIO_ROOT_PASSWORD": "root-pass-1"})
    assert started.returncode == 0 and started.stdout.startswith("minio server /data"), started


@needs_sh
def test_minio_init_refuses_an_empty_root_pair_before_anything_else(services):
    run = _run(_script(services, "minio-init"), {})
    assert run.returncode == 1
    assert run.stderr.startswith("minio-init: MINIO_ROOT_USER or MINIO_ROOT_PASSWORD is empty")
    assert "minio.env" in run.stderr and "release/install.sh --production-secrets" in run.stderr


@needs_sh
def test_redis_without_its_file_refuses_and_names_the_step(tmp_path):
    code, _out, err, acl = run_start_script({"REDIS_PASSWORD": "", "REDIS_URL": ""}, tmp_path)
    assert code == 1 and acl == ""
    assert "REDIS_PASSWORD is empty" in err and "redis.env" in err
    assert "release/install.sh" in err and "--production-secrets" in err
