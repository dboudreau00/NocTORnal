"""Where the production stack's TLS material is mounted, and how each hop inside it is encrypted.

Static: infra/production/compose.yml is read with test_egress_topology.Reader, which fails closed on a
construct it does not understand. scripts/internal_tls.py lays the material out under
infra/production/tls (test_internal_tls_script.py holds the layout and the modes); this file holds
that compose mounts each part where it belongs:

* `tls/public` (the CA every client trusts, and no key) into the clients, at /certs;
* each server's key directory into that server alone;
* `tls/ca` (the CA's key) and the old self-signed pair `migrate` keeps nowhere.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from test_egress_topology import Reader

ROOT = Path(__file__).resolve().parents[3]
PRODUCTION = ROOT / "infra" / "production"
COMPOSE = PRODUCTION / "compose.yml"
SCRIPT = ROOT / "scripts" / "internal_tls.py"

#: Each server that terminates TLS inside the compose network, and the directory under tls/ that
#: holds its key (scripts/internal_tls.py SERVERS).
KEY_DIRECTORIES = {"minio": "tls/minio", "minio-filter": "tls/minio",
                   "postgres": "tls/postgres", "redis": "tls/redis"}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


@pytest.fixture(scope="module")
def services() -> dict:
    return Reader(_text(COMPOSE)).document()["services"]


def _bind_mounts(service: dict) -> list[tuple[str, str]]:
    """(source relative to infra/production, target) for every bind mount of `service`."""
    out = []
    for volume in service.get("volumes", []) or []:
        source, _, rest = str(volume).partition(":")
        if source.startswith("."):
            target = rest.split(":")[0]
            out.append((os.path.normpath(source).replace("\\", "/"), target))
    return out


def _under_tls(source: str) -> bool:
    return source == "tls" or source.startswith("tls/")


def test_no_application_container_mounts_a_private_key(services):
    """The clients mount tls/public, which holds the CA and no key; no client mounts tls/ whole, a
    server's key directory or the CA's."""
    for name, service in services.items():
        for source, target in _bind_mounts(service):
            if not _under_tls(source) or name in KEY_DIRECTORIES:
                continue
            assert source == "tls/public", (name, source)
            assert target == "/certs", (name, target)
            assert f"./{source}:{target}:ro" in service["volumes"], (name, "read-only")


def test_each_server_mounts_only_its_own_key_directory(services):
    for name, service in services.items():
        mounted = {source for source, _ in _bind_mounts(service)
                   if _under_tls(source) and source != "tls/public"}
        expected = {KEY_DIRECTORIES[name]} if name in KEY_DIRECTORIES else set()
        assert mounted == expected, (name, mounted)
    minio = dict(_bind_mounts(services["minio"]))
    assert minio == {"tls/minio": "/root/.minio/certs"}, minio
    assert "./tls/minio:/root/.minio/certs:ro" in services["minio"]["volumes"]
    assert dict(_bind_mounts(services["minio-filter"]))["tls/minio"] == "/certs"
    assert "./tls/minio:/certs:ro" in services["minio-filter"]["volumes"]
    assert "./tls/postgres:/pg-tls-src:ro" in services["postgres"]["volumes"]
    assert "./tls/redis:/tls:ro" in services["redis"]["volumes"]


def test_the_ca_key_and_the_old_pair_are_mounted_nowhere(services):
    for name, service in services.items():
        for source, _target in _bind_mounts(service):
            assert source != "tls", (name, "tls/ is never mounted whole")
            assert not source.startswith(("tls/ca", "tls/legacy-minio")), (name, source)


def test_the_public_tls_directory_mounted_into_clients_holds_no_key():
    """What compose mounts as tls/public is what the script writes there, the CA alone, and the
    script's `check` fails a key found in it."""
    source = _text(SCRIPT)
    assert 'PUBLIC = "public"' in source and 'BUNDLE = "ca.crt"' in source
    assert "holds a private key, and that directory is" in source


def test_the_secrets_template_puts_minios_certificate_in_tls_minio():
    """MINIO_SECURE's comment names where MinIO's pair now sits; ./tls itself is mounted nowhere."""
    template = _text(PRODUCTION / "secrets.env.example")
    assert "no certificate in ./tls/minio" in template
    assert "no certificate in ./tls " not in template.replace("\n", " ")


def test_every_client_trusts_the_ca_from_the_public_mount(services):
    """Each service that builds a trust bundle at start reads /certs/ca.crt, the file in tls/public;
    the old /certs/public.crt is MinIO's own certificate and no longer mounted anywhere."""
    builders = []
    for name, service in services.items():
        for key in ("command", "entrypoint"):
            value = service.get(key)
            script = value[-1] if isinstance(value, list) and value else value
            if isinstance(script, str) and "ca-bundle.crt" in script:
                builders.append(name)
                assert "cat /etc/ssl/certs/ca-certificates.crt /certs/ca.crt > /tmp/ca-bundle.crt" \
                    in script, name
                assert "/certs/public.crt" not in script, name
    assert sorted(builders) == ["api", "collector", "cron", "embed-pass", "lab-cron",
                                "lab-triage", "sample-origin"], builders
    alias = _text(PRODUCTION / "mc-alias.sh")
    assert '"${MC_CERTIFICATE:-/certs/ca.crt}"' in alias


# ---------------------------------------------------------------------------
# Caddy, the TLS terminator the internet reaches first, runs unprivileged
# ---------------------------------------------------------------------------

CADDY_UID = "10002"


def test_caddy_runs_as_the_unprivileged_uid_and_binds_low_ports_by_sysctl(services):
    """uid 10002, not root. The binary carries NET_BIND_SERVICE as a file capability and the kernel
    refuses to exec it unless the capability is in the bounding set, so it stays in cap_add; under
    no-new-privileges a non-root exec is not granted it, so the namespaced sysctl is what lets the
    process bind 80 and 443."""
    caddy = services["caddy"]
    assert caddy["user"] == f"{CADDY_UID}:{CADDY_UID}"
    assert caddy["cap_drop"] == ["ALL"] and caddy["cap_add"] == ["NET_BIND_SERVICE"]
    assert "no-new-privileges:true" in caddy["security_opt"]
    assert caddy["sysctls"] == {"net.ipv4.ip_unprivileged_port_start": "0"}
    assert caddy["read_only"] is True


def test_caddy_init_may_only_chown_the_two_caddy_volumes(services):
    init, caddy = services["caddy-init"], services["caddy"]
    assert init["image"] == caddy["image"], "the same pinned image, so the same chown"
    assert init["user"] == "0:0" and init["restart"] == "no"
    assert init["cap_drop"] == ["ALL"] and init["cap_add"] == ["CHOWN", "DAC_READ_SEARCH"]
    assert "no-new-privileges:true" in init["security_opt"] and init["read_only"] is True
    assert init["network_mode"] == "none" and "networks" not in init
    assert "env_file" not in init and "ports" not in init
    assert init["entrypoint"] == ["chown", "-R", f"{CADDY_UID}:{CADDY_UID}", "/data", "/config"]
    assert "command" not in init
    assert init["volumes"] == ["caddy-data:/data", "caddy-config:/config"]
    named = [v for v in caddy["volumes"] if not str(v).startswith(".")]
    assert named == init["volumes"], "it owns exactly the volumes Caddy writes"


def test_caddy_init_can_rerun_over_the_volumes_caddy_has_written(services):
    """Caddy makes its storage directories mode 0700 as uid 10002, and root without DAC_READ_SEARCH
    cannot open a directory it does not own, so the second `up` failed the recursive chown and
    Caddy, which waits for it, never started. DAC_READ_SEARCH opens and reads; DAC_OVERRIDE and
    FOWNER, which would let it write, stay out. The README gives the lab check."""
    caps = set(services["caddy-init"]["cap_add"])
    assert "DAC_READ_SEARCH" in caps
    assert not caps & {"DAC_OVERRIDE", "FOWNER"}
    readme = _text(PRODUCTION / "README.md")
    assert "compose.yml run --rm caddy-init" in readme


def test_caddy_waits_for_caddy_init(services):
    depends = services["caddy"]["depends_on"]
    assert depends["caddy-init"] == {"condition": "service_completed_successfully"}
    assert depends["api"] == {"condition": "service_started"}
    assert depends["sample-origin"] == {"condition": "service_started"}


# ---------------------------------------------------------------------------
# Postgres: TLS 1.3 from the network, and nothing else
# ---------------------------------------------------------------------------

def _postgres_flags(services) -> dict[str, str]:
    words = " ".join(services["postgres"]["command"].split()).split()
    assert words[0] == "postgres"
    flags = {}
    for flag, setting in zip(words[1::2], words[2::2], strict=True):
        assert flag == "-c", words
        name, _, value = setting.partition("=")
        flags[name] = value
    return flags


def test_postgres_serves_tls_1_3_and_reads_the_hba_file(services):
    flags = _postgres_flags(services)
    assert flags["ssl"] == "on"
    assert flags["ssl_min_protocol_version"] == "TLSv1.3"
    assert flags["ssl_cert_file"] == "/run/pg-tls/server.crt"
    assert flags["ssl_key_file"] == "/run/pg-tls/server.key"
    # A flag, not the volume's own pg_hba.conf, so an existing volume gets it too.
    assert flags["hba_file"] == "/etc/postgresql/pg_hba.conf"
    assert "./pg_hba.conf:/etc/postgresql/pg_hba.conf:ro" in services["postgres"]["volumes"]


def _hba_rules() -> list[list[str]]:
    lines = _text(PRODUCTION / "pg_hba.conf").splitlines()
    return [line.split() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def test_pg_hba_allows_only_hostssl_from_the_network():
    """Inside the container, the socket and the loopback address, as the image's initdb allows (the
    healthcheck, db/init and the README's psql, pg_dump and pg_restore run there); from the network,
    TLS and a password alone. No `host` rule for another address, so a client that leaves sslmode out
    is refused by the server, and no `hostnossl`, `trust` or `password` from the network."""
    rules = _hba_rules()
    local = [r for r in rules if r[0] == "local"]
    network = [r for r in rules if r[0] != "local"]
    assert local == [["local", "all", "all", "trust"]]
    loopback = [r for r in network if r[0] == "host"]
    assert loopback == [["host", "all", "all", "127.0.0.1/32", "trust"],
                        ["host", "all", "all", "::1/128", "trust"]], loopback
    remote = [r for r in network if r[0] != "host"]
    assert remote == [["hostssl", "all", "all", "all", "scram-sha-256"]], remote


def test_postgres_key_is_copied_to_a_tmpfs_owned_by_the_postgres_user(services):
    """Postgres refuses a key that is not its own user's at 0600 (or root's at 0640), and the host's
    copy is root's at 0600, so the entrypoint copies the pair, as root, onto a tmpfs: never onto a
    disk, and owned by the image's postgres user before the image's own entrypoint starts."""
    postgres = services["postgres"]
    assert postgres["tmpfs"] == ["/run/pg-tls:size=1m,mode=0700,noexec,nosuid,nodev"]
    entry = postgres["entrypoint"]
    assert entry[:2] == ["/bin/sh", "-c"] and entry[3] == "noctornal-postgres" and len(entry) == 4
    script = [line.strip() for line in entry[2].replace("$$", "$").splitlines() if line.strip()]
    assert script == [
        "set -e",
        "install -d -m 0700 -o postgres -g postgres /run/pg-tls",
        "install -m 0644 -o postgres -g postgres /pg-tls-src/server.crt /run/pg-tls/server.crt",
        "install -m 0600 -o postgres -g postgres /pg-tls-src/server.key /run/pg-tls/server.key",
        'exec docker-entrypoint.sh "$@"',
    ], script
    # The copy needs CHOWN and DAC_OVERRIDE, which the image's entrypoint already held: no
    # capability was added for it.
    assert set(postgres["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}


def test_the_egress_proxy_mounts_the_public_ca_only(services):
    """Its database hop is verify-full, so it trusts the CA; it holds none of the application's
    files and no key."""
    assert services["egress-proxy"]["volumes"] == ["./tls/public:/certs:ro"]


def test_every_dsn_in_the_templates_names_verify_full_and_the_ca_file(services):
    from noctornal_api import config

    assert config.DATABASE_CA_FILE == "/certs/ca.crt", "the file tls/public mounts at /certs"
    found = {}
    for name in ("secrets.env.example", "migrate.env.example", "egress-proxy.env.example"):
        for line in _text(PRODUCTION / name).splitlines():
            key, _, value = line.partition("=")
            if key.endswith("DATABASE_URL"):
                found[key] = value
    assert set(found) == {"DATABASE_URL", "NOCTORNAL_WORKER_DATABASE_URL",
                          "NOCTORNAL_MIGRATION_DATABASE_URL", "NOCTORNAL_EGRESS_DATABASE_URL"}
    for key, dsn in found.items():
        assert dsn.endswith("@postgres:5432/noctornal?" + config.DATABASE_TLS_QUERY), key
        assert config.database_hop(dsn, {}) == "verified", key
    # Every service that holds one of them mounts the CA it names.
    for name, service in services.items():
        if name in ("api", "sample-origin", "cron", "collector", "lab-triage", "lab-cron",
                    "embed-pass", "migrate", "egress-proxy"):
            assert "./tls/public:/certs:ro" in service["volumes"], name


# ---------------------------------------------------------------------------
# Caddy has no route out, and shares a network with the two processes it proxies to alone
# ---------------------------------------------------------------------------

def _members(services: dict, network: str) -> set[str]:
    out = set()
    for name, service in services.items():
        nets = service.get("networks") or []
        if network in (nets if isinstance(nets, (list, dict)) else []):
            out.add(name)
    return out


@pytest.fixture(scope="module")
def doc() -> dict:
    return Reader(_text(COMPOSE)).document()


def test_caddy_is_on_frontend_and_ingress_only(services, doc):
    nets = services["caddy"]["networks"]
    assert set(nets) == {"frontend", "ingress"}
    assert nets["frontend"] == {"ipv4_address": doc["x-caddy-ip"]}
    assert not nets["ingress"]
    assert services["caddy"]["ports"] == ["80:80", "443:443"]


def test_ingress_has_no_masquerade_and_frontend_is_internal(doc):
    """`frontend` is internal: nothing on it has a route out. `ingress` cannot be internal, or Docker
    would publish no port on it, so it is a bridge whose traffic is not given the host's address on the
    way out: a connection Caddy starts leaves with an unroutable private source, which the README's
    DOCKER-USER rule then drops on the host."""
    networks = doc["networks"]
    assert networks["frontend"]["internal"] is True
    assert "driver_opts" not in networks["frontend"]
    assert networks["ingress"].get("internal", False) is False
    assert networks["ingress"]["driver_opts"] == {
        "com.docker.network.bridge.enable_ip_masquerade": "false"}


def test_only_caddy_joins_ingress_and_only_caddy_api_and_sample_origin_join_frontend(services):
    assert _members(services, "ingress") == {"caddy"}
    assert _members(services, "frontend") == {"caddy", "api", "sample-origin"}


def test_caddy_shares_no_network_with_postgres_redis_minio_or_the_egress_proxy(services):
    caddy = set(services["caddy"]["networks"])
    for name in ("postgres", "redis", "minio", "minio-init", "egress-proxy", "migrate", "cron",
                 "collector", "lab-triage", "lab-cron", "embed-pass"):
        nets = services[name].get("networks") or []
        assert not caddy & set(nets), name
    assert "edge" not in caddy and "noctornal" not in caddy


def test_the_acme_override_is_the_only_file_that_gives_caddy_the_edge_network(doc):
    """Read as text: the compose reader does not read the `!override` tag, so this fails closed on any
    shape but the one written, which replaces Caddy's networks with `frontend` at x-caddy-ip and `edge`,
    and touches nothing else."""
    text = _text(PRODUCTION / "compose.acme.yml")
    code = [line.rstrip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    assert code == [
        "services:",
        "  caddy:",
        "    networks: !override",
        "      frontend:",
        f'        ipv4_address: "{doc["x-caddy-ip"]}"',
        "      edge: {}",
    ], code
    assert "edge:" not in "\n".join(
        line for line in _text(COMPOSE).split("\n  caddy:\n", 1)[1].split("\n  postgres:", 1)[0]
        .splitlines() if not line.lstrip().startswith("#"))
    readme = _text(PRODUCTION / "README.md")
    assert "compose.acme.yml" in readme and "NOCTORNAL_TLS_MODE" in readme
    caddy_env = _text(PRODUCTION / "caddy.env.example")
    assert "compose.acme.yml" in caddy_env


def test_the_upgrade_issues_the_certificates_then_takes_the_stack_down_before_up():
    """The release moves MinIO's key and Caddy's fixed address to a new network, so an existing
    deployment migrates the TLS directory, rewrites its secrets files, and only then goes down and up:
    a plain `up -d --build` recreates networks under running containers and leaves the stack half
    started."""
    readme = _text(PRODUCTION / "README.md")
    section = readme.split("### From a release before 2026-11-15: the internal CA", 1)[1]
    section = section.split("\n### ", 1)[0]
    block = section.split("```sh\n", 1)[1].split("```", 1)[0]
    order = ["internal_tls.py migrate", "internal_tls.py check", "--production-secrets",
             "compose.yml down", "compose.yml up -d --build"]
    positions = [block.index(step) for step in order]
    assert positions == sorted(positions), block
    assert "Do not skip the `down`" in section and "compose.acme.yml" in section


def test_the_docker_user_rule_is_described_and_installed_by_nothing():
    """The owner's decision: the host rule that drops connections Caddy starts is the operator's to add,
    so the README states it and no script or compose file runs it."""
    rule = "iptables -I DOCKER-USER -s 172.31.248.0/24 -m conntrack --ctstate NEW -j DROP"
    assert rule in _text(PRODUCTION / "README.md")
    for folder in ("infra", "scripts", "release"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and path.suffix in (".sh", ".py", ".ps1", ".yml", ".yaml", ""):
                try:
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                assert "DOCKER-USER" not in text, path
