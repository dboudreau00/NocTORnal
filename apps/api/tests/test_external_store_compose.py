"""`infra/production/compose.external-store.yml`: the production stack on a store other than the bundled MinIO.

Read as text through the repository's YAML reader (`test_egress_topology.Reader`), with Compose's `!reset` tag
stood in for, since the reader takes the base file's subset and no tags. The override is checked against the base
file so the two cannot drift: what it removes, what it keeps, and that the gate it puts in minio-init's place is
the same kind of gate. `docker compose config` on Compose 2.40 renders the merge as these tests describe it
(docs/22 records the run).
"""
from __future__ import annotations

from pathlib import Path

from test_egress_topology import Reader

ROOT = Path(__file__).resolve().parents[3]
PRODUCTION = ROOT / "infra" / "production"
BASE = PRODUCTION / "compose.yml"
OVERRIDE = PRODUCTION / "compose.external-store.yml"
RESET = "RESET-BY-OVERRIDE"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _base() -> dict:
    return Reader(_text(BASE)).document()["services"]


def _override() -> dict:
    text = _text(OVERRIDE)
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert body.count("!reset null") == 2, "a !reset this test does not know about"
    assert "!" not in body.replace("!reset null", ""), (
        "a Compose tag this test cannot read; it fails closed on a shape it does not expect")
    return Reader(text.replace("!reset null", RESET)).document()["services"]


def test_the_override_inactivates_minio_and_minio_init():
    services = _override()
    for name in ("minio", "minio-init"):
        assert services[name] == {"profiles": ["bundled-store"]}, services[name]


def test_api_and_sample_origin_keep_every_dependency_but_minio_init():
    base, override = _base(), _override()
    for name in ("api", "sample-origin"):
        assert "minio-init" in base[name]["depends_on"], name
        assert set(override[name]) == {"depends_on"}, f"{name}: the override changes more than its gate"
        deps = override[name]["depends_on"]
        assert set(deps) == {"minio-init", "object-store-init"}, deps
        assert deps["minio-init"] == RESET, "minio-init must be removed, not changed"
        # Every other dependency comes from the base file untouched: Compose merges depends_on by key.
        kept = set(base[name]["depends_on"]) - {"minio-init"}
        assert kept and "migrate" in kept and "redis" in kept, kept


def test_object_store_init_gates_api_and_sample_origin_on_success():
    override = _override()
    for name in ("api", "sample-origin"):
        gate = override[name]["depends_on"]["object-store-init"]
        assert gate == {"condition": "service_completed_successfully"}, gate
    service = override["object-store-init"]
    assert service["restart"] == "no"
    script = service["command"][-1]
    assert "exec python scripts/object_store_provision.py" in script
    assert "--apply" not in script, "the gate checks; making buckets is an administrator's act"


def test_the_base_file_does_not_make_the_dependency_optional():
    """`required: false` on a dependency would let the API start after a failed init."""
    for name, service in _base().items():
        for dep, how in (service.get("depends_on") or {}).items() if isinstance(
                service.get("depends_on"), dict) else ():
            assert not (isinstance(how, dict) and how.get("required") in (False, "false")), (name, dep)
    for name, service in _override().items():
        deps = service.get("depends_on")
        if isinstance(deps, dict):
            for dep, how in deps.items():
                assert not (isinstance(how, dict) and "required" in how), (name, dep)


def test_object_store_init_holds_no_database_credential_and_mounts_only_the_public_tls_directory():
    service = _override()["object-store-init"]
    env = service["environment"]
    for name in ("POSTGRES_PASSWORD", "NOCTORNAL_MIGRATION_DATABASE_URL", "DATABASE_URL",
                 "NOCTORNAL_WORKER_DATABASE_URL"):
        assert env[name] == "", name
    assert service["volumes"] == ["./tls:/certs:ro"]
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["networks"] == ["noctornal"]
    assert "ports" not in service


def test_object_store_init_holds_no_key_pepper_mail_cache_or_root_secret():
    """secrets.env reaches it whole (env_file cannot filter), so every secret that is not the store's is emptied
    in `environment`, which wins over env_file."""
    env = _override()["object-store-init"]["environment"]
    for name in ("NOCTORNAL_APP_DB_PASSWORD", "NOCTORNAL_TOTP_KEK", "NOCTORNAL_INGEST_PEPPER", "REDIS_PASSWORD",
                 "REDIS_URL", "SMTP_PASSWORD", "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"):
        assert env[name] == "", name
    for name in ("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY", "OBJECT_STORE_ACCESS_KEY",
                 "OBJECT_STORE_SECRET_KEY", "SAMPLE_ACCESS_KEY", "PRESERVE_ACCESS_KEY"):
        assert name not in env, f"{name} is the store's own and must reach the check"


def test_the_override_runs_the_image_the_base_file_runs():
    base_text = _text(BASE)
    image = next(line.split("image:", 1)[1].strip() for line in base_text.splitlines()
                 if line.strip().startswith("image: noctornal-api:"))
    service = _override()["object-store-init"]
    assert service["image"] == image and service["pull_policy"] == "never"
    assert service["logging"]["options"] == {"max-size": "10m", "max-file": "5"}


def test_the_admin_env_file_is_ignored_by_git_and_docker():
    service = _override()["object-store-init"]
    assert {"path": "object-store-admin.env", "required": False} in service["env_file"]
    gitignore = _text(ROOT / ".gitignore").splitlines()
    dockerignore = _text(ROOT / ".dockerignore").splitlines()
    assert "*.env" in gitignore
    assert "**/*.env" in dockerignore


def test_the_new_service_name_is_reserved_from_integration_rules():
    from noctornal_api.egress_policy import RESERVED_SERVICE_NAMES
    assert "object-store-init" in RESERVED_SERVICE_NAMES
