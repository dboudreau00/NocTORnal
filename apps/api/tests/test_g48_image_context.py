"""What reaches an image, what the production stack is allowed to do, and what
is kept off command lines (infra-1, 2, 5, 6, 7, 8 and 10, 2026-10-03).

Static: the compose files, the Caddyfile, the Dockerfile, the ignore files,
the init scripts and the README are read as text, and the two small shell
files are run with a POSIX shell where one is installed. Nothing here needs
Docker; the proofs that did (a real build context, a real Caddy, a real
Postgres and MinIO under the dropped capabilities) are in the report.

The compose reader is `test_egress_topology.Reader`, which fails closed on a
construct it does not understand.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from test_egress_topology import APP_ONLY, Reader

ROOT = Path(__file__).resolve().parents[3]
PRODUCTION = ROOT / "infra" / "production"
COMPOSE = PRODUCTION / "compose.yml"
DEV_COMPOSE = ROOT / "infra" / "docker-compose.yml"
CADDYFILE = PRODUCTION / "Caddyfile"
README = PRODUCTION / "README.md"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _services() -> dict:
    return Reader(_text(COMPOSE)).document()["services"]


def _script(service: str, key: str) -> str:
    value = _services()[service][key]
    script = value[-1] if isinstance(value, list) else value
    return script.replace("$$", "$")


# ---------------------------------------------------------------------------
# infra-1 and infra-2: what may reach the build context
# ---------------------------------------------------------------------------

class Dockerignore:
    """The part of Docker's `.dockerignore` rules this repository uses: `*`
    and `?` stop at a slash, `**` crosses directories, a pattern that
    matches a directory excludes everything under it, `!` re-includes, and
    the last rule that matches wins. Every pattern is anchored at the
    context root, so `*.sql` is a root-level rule."""

    def __init__(self, text: str):
        self.rules: list[tuple[bool, re.Pattern]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            pattern = line[1:] if negate else line
            self.rules.append((negate, self._compile(pattern.strip("/"))))

    @staticmethod
    def _compile(pattern: str) -> re.Pattern:
        out = []
        segments = pattern.split("/")
        for i, segment in enumerate(segments):
            if segment == "**":
                out.append(".*" if i == len(segments) - 1 else "(?:.*/)?")
                continue
            piece = "".join("[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch)
                            for ch in segment)
            out.append(piece + ("/" if i < len(segments) - 1 else ""))
        return re.compile("".join(out))

    def excluded(self, path: str) -> bool:
        parts = path.strip("/").split("/")
        candidates = ["/".join(parts[:n]) for n in range(1, len(parts) + 1)]
        verdict = False
        for negate, regex in self.rules:
            if any(regex.fullmatch(candidate) for candidate in candidates):
                verdict = not negate
        return verdict


@pytest.mark.parametrize("rules,path,excluded", [
    (["*.sql"], "noctornal-1.sql", True),
    (["*.sql"], "db/schema.sql", False),          # root-level only, as Docker reads it
    (["*.sql.*"], "dump.sql.gz", True),
    (["infra/production/*.env"], "infra/production/egress-proxy.env", True),
    (["infra/production/*.env"], "infra/production/egress-proxy.env.example", False),
    (["**/*.key"], "a/b/c.key", True),
    (["**/*.key"], "c.key", True),
    (["infra/production/tls/"], "infra/production/tls/private.key", True),
    (["backup/"], "backup/x/y", True),
    (["*.sql", "!keep.sql"], "keep.sql", False),
    (["noctornal-*"], "noctornal-20261002T120000Z.dump.age", True),
    (["noctornal-*"], "apps/noctornal-x", False),
])
def test_the_dockerignore_matcher_reads_rules_as_docker_does(rules, path, excluded):
    assert Dockerignore("\n".join(rules)).excluded(path) is excluded


def _gitignored_secret_paths() -> list[str]:
    paths = []
    for line in _text(ROOT / ".gitignore").splitlines():
        line = line.strip()
        if line.startswith("infra/production/") and not line.startswith("#"):
            # A directory rule is probed with a file inside it.
            paths.append(line + "private.key" if line.endswith("/") else line)
    return paths


def test_every_gitignored_secret_under_infra_production_is_also_dockerignored():
    """`.dockerignore` was written for the older layout and stopped at
    secrets.env and tls/, so after S2 (2026-09-24) every image carried the
    BYPASSRLS role's password and the egress proxy's seal key. A path added
    to .gitignore without a line in .dockerignore fails here."""
    paths = _gitignored_secret_paths()
    assert {"infra/production/secrets.env", "infra/production/egress-proxy.env",
            "infra/production/egress-client.env", "infra/production/postgres-init.env",
            "infra/production/caddy.env", "infra/production/tls/private.key"} <= set(paths), paths
    ignore = Dockerignore(_text(ROOT / ".dockerignore"))
    not_ignored = [p for p in paths if not ignore.excluded(p)]
    assert not not_ignored, f".gitignore hides these but .dockerignore does not: {not_ignored}"


def test_a_secret_file_nobody_listed_is_excluded_too():
    """The pattern, not only the names: the next file the directory gets (the
    owner's password, when F52 moves it) is excluded before anyone remembers."""
    ignore = Dockerignore(_text(ROOT / ".dockerignore"))
    assert ignore.excluded("infra/production/migrate.env")
    assert ignore.excluded("infra/production/anything/else.key")
    assert ignore.excluded("some/vendored/dir/cert.pem")


def test_the_templates_stay_in_the_image_context():
    """Excluding `*.env` must not take the tracked `.env.example` templates
    or anything the image needs."""
    ignore = Dockerignore(_text(ROOT / ".dockerignore"))
    for path in ("infra/production/secrets.env.example", "infra/production/caddy.env.example",
                 "infra/production/egress-proxy.env.example",
                 "constraints.txt", "alembic.ini", "Dockerfile",
                 "apps/api/pyproject.toml", "packages/ontology/pyproject.toml",
                 "db/migrations/env.py", "db/schema.sql", "db/init/00-extensions.sql",
                 "scripts/launch.sh", "yara/sources.json"):
        assert not ignore.excluded(path), f"{path} would no longer reach the image"


@pytest.mark.parametrize("name", [
    "noctornal-20261002T120000Z.sql",            # the documented backup's old name
    "noctornal-20261002T120000Z.dump.age",       # and its new one
    "dump.sql", "dump.sql.gz", "case.dump", "case.dump.gpg", "backup/evidence/x", "backups/y",
])
def test_a_database_dump_or_backup_at_the_root_never_reaches_the_image(name):
    assert Dockerignore(_text(ROOT / ".dockerignore")).excluded(name)


def _git_ignored(path: str) -> bool | None:
    if shutil.which("git") is None:
        return None
    probe = subprocess.run(["git", "rev-parse", "--git-dir"], cwd=ROOT, capture_output=True)
    if probe.returncode != 0:
        return None
    done = subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=ROOT,
                          capture_output=True)
    return done.returncode == 0


@pytest.mark.parametrize("name", [
    "noctornal-20261002T120000Z.sql", "noctornal-20261002T120000Z.dump.age", "case.dump",
    "dump.sql.gz", "backup/evidence/x", "infra/production/caddy.env",
    "infra/production/postgres-init.env",
])
def test_git_refuses_a_stray_dump_too(name):
    """`git add -A`, which the tree-transfer scripts use, must not stage one."""
    ignored = _git_ignored(name)
    if ignored is None:
        pytest.skip("not a git checkout")
    assert ignored, name
    assert _git_ignored("db/schema.sql") is False, "a bare *.sql would hide db/"


def _backup_section() -> str:
    text = _text(README)
    start = text.index("**Backups, nothing here does this for you.**")
    return text[start:text.index("**Stopping.**", start)]


def test_the_documented_backup_never_writes_a_dump_into_the_checkout():
    section = _backup_section()
    blocks = re.findall(r"```sh\n(.*?)```", section, flags=re.S)
    assert blocks, "the backup section lost its commands"
    code = "\n".join(blocks)
    # The old shape, in every spelling that lands in the working directory.
    assert not re.search(r">\s*(\./)?noctornal-", code), code
    for target in re.findall(r"(?<![0-9&])>\s*(\S+)", code):
        assert target.startswith(("/srv/", "/dev/null")), f"redirects into {target}"
    assert "/srv/noctornal-backup/noctornal-" in code


def test_the_documented_backup_is_private_and_encrypted_and_says_where_it_goes():
    section = _backup_section()
    code = "\n".join(re.findall(r"```sh\n(.*?)```", section, flags=re.S))
    assert code.count("umask 077") >= 2, "the host shell and the container script both set it"
    assert "install -d -m 0700 /srv/noctornal-backup" in code
    # Encryption sits between pg_dump and the file it lands in.
    assert re.search(r"pg_dump -Fc .*\n\s*\| age -r \S+ \\\n\s*> /srv/", code), code
    assert "--passphrase " not in section, "a passphrase on a command line is readable by ps"
    for sentence in ("Outside the checkout", "build context", "Private from the first byte",
                     "Encrypted before it reaches a disk", "0700"):
        assert sentence in section or sentence in code, sentence


def test_no_documented_command_passes_the_minio_root_password_as_an_argument():
    for path in (README, COMPOSE):
        code = "\n".join(line for line in _text(path).splitlines()
                         if not line.lstrip().startswith("#"))
        assert "mc alias set" not in code, path
    # The compose file's own code (comments aside) never expands the password,
    # except in the sentence minio-init prints when its wait gives up.
    code = [line for line in _text(COMPOSE).splitlines() if not line.lstrip().startswith("#")]
    expanded = [line for line in code if re.search(r"\$\$?\{?MINIO_ROOT_PASSWORD", line)]
    assert expanded == [], expanded
    assert "mc_setup" in _backup_section()


# ---------------------------------------------------------------------------
# infra-5: capabilities, and what Caddy holds
# ---------------------------------------------------------------------------

#: service -> the capabilities it keeps after `cap_drop: [ALL]`, and why
#: (infra/production/README.md, Hardening). Everything else keeps none.
_KEPT = {
    "caddy": {"NET_BIND_SERVICE"},
    "postgres": {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
    "redis": {"DAC_OVERRIDE"},
    # The isolated analysis worker (docs/17 F42): root, so that it can give
    # each child a user of its own and stop that user's processes. Held, with
    # the rest of what makes it a sandbox, by test_analysis_worker_compose.
    "analysis-worker": {"KILL", "SETGID", "SETUID"},
}


def test_every_service_drops_all_capabilities_and_keeps_only_what_is_listed():
    services = _services()
    assert set(services) == set(APP_ONLY) | {"caddy", "egress-proxy", "analysis-worker"}
    for name, service in services.items():
        assert service.get("cap_drop") == ["ALL"], name
        assert set(service.get("cap_add") or []) == _KEPT.get(name, set()), name
        assert "no-new-privileges:true" in service.get("security_opt", []), name


def test_one_service_builds_the_application_image_and_none_pulls_it():
    """Beta 1 deployment gate (2026-10-07): with a `build:` on every service
    of the application image, Compose 2.40 on Docker 29's containerd image
    store exported the one tag from several bake targets, and the first
    `up -d --build` of a fresh host failed with `image ... already exists`.
    One builder, and every other service of that image never pulls it (there
    is no registry copy of a tag only this host builds)."""
    services = _services()
    builders = {name: s for name, s in services.items() if "build" in s}
    assert set(builders) == {"migrate"}, sorted(builders)
    assert builders["migrate"]["build"] == {"context": "../..", "dockerfile": "Dockerfile"}
    assert builders["migrate"].get("pull_policy") == "missing"
    image = builders["migrate"]["image"]
    users = {name for name, s in services.items() if s.get("image") == image}
    assert users == set(APP_ONLY) - {"postgres", "redis", "minio", "minio-init"} \
        | {"egress-proxy", "analysis-worker"}, sorted(users)
    for name in users - {"migrate"}:
        assert services[name].get("pull_policy") == "never", name


def test_every_container_log_is_bounded():
    """Beta 1 deployment gate (2026-10-07): Docker's json-file driver keeps
    a container's output without limit by default, and nothing on the host
    set one, so a deployment left alone filled its disk with loop and slow
    statement logs."""
    for name, service in _services().items():
        logging = service.get("logging") or {}
        assert logging.get("driver") == "json-file", name
        options = logging.get("options") or {}
        assert re.fullmatch(r"\d+m", str(options.get("max-size", ""))), name
        assert 1 <= int(options.get("max-file", 0)) <= 10, name


def test_net_raw_is_in_no_service_the_internet_can_reach_first():
    caddy = _services()["caddy"]
    assert "NET_RAW" not in (caddy.get("cap_add") or [])
    assert caddy.get("cap_drop") == ["ALL"] and str(caddy.get("read_only")).lower() == "true"


def test_caddy_holds_its_own_three_values_and_none_of_the_platforms():
    caddy = _services()["caddy"]
    assert caddy["env_file"] == ["caddy.env"]
    template = _text(PRODUCTION / "caddy.env.example")
    names = re.findall(r"(?m)^([A-Z][A-Z0-9_]*)=", template)
    assert sorted(names) == ["NOCTORNAL_HOSTNAME", "NOCTORNAL_SAMPLE_HOSTNAME",
                             "NOCTORNAL_TLS_MODE"]
    secrets = _text(PRODUCTION / "secrets.env.example")
    for name in names:
        assert not re.search(rf"(?m)^{name}=", secrets), f"{name} is still in secrets.env"
    # Every placeholder the Caddyfile reads is one of them.
    used = set(re.findall(r"\{\$(NOCTORNAL_[A-Z_]+)", _text(CADDYFILE)))
    assert used == set(names), used


# ---------------------------------------------------------------------------
# infra-6: HSTS and TLS 1.3 where the shipped terminator sends them
# ---------------------------------------------------------------------------

def _site_blocks() -> dict[str, str]:
    text = _text(CADDYFILE)
    return {m.group(1): m.group(2)
            for m in re.finditer(r"(?ms)^\{\$(NOCTORNAL_\w*HOSTNAME)\} \{\n(.*?)^\}", text)}


def test_caddy_keeps_the_csrf_and_setup_tokens_out_of_its_log():
    """Beta 1 deployment gate (2026-10-07): on a 502 Caddy logs the request's
    headers, redacting Cookie and Authorization alone, so X-Csrf-Token and
    X-Setup-Token reached `docker logs` verbatim. The global block's log
    filter deletes both (shown against the pinned Caddy, 2.11.4)."""
    text = _text(CADDYFILE)
    glob = re.match(r"(?ms)^\{\n(.*?)^\}", text[text.index("\n{\n") + 1:]).group(1)
    assert re.search(r"log \{\s*format filter \{\s*wrap json\s*fields \{", glob), glob
    for header in ("X-Csrf-Token", "X-Setup-Token"):
        assert re.search(rf"(?m)^\s*request>headers>{header} delete$", glob), header


def test_both_hostnames_send_hsts_and_speak_tls_13_only():
    blocks = _site_blocks()
    assert set(blocks) == {"NOCTORNAL_HOSTNAME", "NOCTORNAL_SAMPLE_HOSTNAME"}
    for name, body in blocks.items():
        match = re.search(r'header Strict-Transport-Security "max-age=(\d+)(; includeSubDomains)?"',
                          body)
        assert match, f"{name} sends no Strict-Transport-Security"
        assert int(match.group(1)) >= 15552000, "less than the six months the preload list asks"
        assert "preload" not in body, "preload is the operator's to choose"
        assert re.search(r"tls \{\$NOCTORNAL_TLS_MODE:internal\} \{\n\s*protocols tls1\.3\n", body), name


def test_http3_is_not_advertised_because_443_udp_is_not_published():
    assert re.search(r"(?s)^\{\n\s*servers \{\n\s*protocols h1 h2\n", _text(CADDYFILE), flags=re.M)
    assert _services()["caddy"]["ports"] == ["80:80", "443:443"]


def test_the_application_still_leaves_hsts_to_the_terminator():
    """If the app ever sends it, this file's header is a duplicate; if it
    never does, the Caddyfile is the only place it can come from."""
    source = _text(ROOT / "apps" / "api" / "src" / "noctornal_api" / "http" / "app.py")
    flat = re.sub(r"\s*\n\s*#?\s*", " ", source)
    assert "HSTS is deliberately left to the TLS terminator" in flat
    assert "Strict-Transport-Security" not in source


# ---------------------------------------------------------------------------
# infra-7: images are pinned by digest
# ---------------------------------------------------------------------------

_DIGEST = re.compile(r"^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")


def test_every_image_the_production_stack_pulls_is_pinned_by_digest():
    pulled = {name: s["image"] for name, s in _services().items()
              if "build" not in s and s.get("pull_policy") != "never"}
    assert set(pulled) == {"caddy", "postgres", "redis", "minio", "minio-init"}, pulled
    unpinned = {n: i for n, i in pulled.items() if not _DIGEST.match(i)}
    assert not unpinned, unpinned


def test_the_dockerfile_base_image_is_pinned_by_digest():
    froms = re.findall(r"(?m)^FROM\s+(\S+)", _text(ROOT / "Dockerfile"))
    assert froms and all(_DIGEST.match(f) for f in froms), froms


# ---------------------------------------------------------------------------
# infra-8: no role logs bind parameters
# ---------------------------------------------------------------------------

def _postgres_command(path: Path) -> str:
    block = re.search(r"(?ms)^  postgres:\n(.*?)^  \S", _text(path) + "\n  x")
    assert block, path
    command = re.search(r"(?ms)^    command: >\n(.*?)^    \S", block.group(1) + "    x")
    assert command, path
    return " ".join(command.group(1).split())


@pytest.mark.parametrize("path", [COMPOSE, DEV_COMPOSE], ids=["production", "development"])
def test_the_cluster_keeps_bind_parameters_out_of_the_log_for_every_role(path):
    """Only noctornal_app carried the setting, so the system role (every cron
    job, sign-in and retention), the egress role and the owner logged a slow
    statement's parameters in full."""
    command = _postgres_command(path)
    assert "-c log_parameter_max_length=0" in command, command
    assert "-c log_parameter_max_length_on_error=0" in command, command
    assert "-c log_min_duration_statement=250" in command


# ---------------------------------------------------------------------------
# infra-10: secrets stay off command lines
# ---------------------------------------------------------------------------

def test_the_redis_healthcheck_passes_the_password_in_the_environment():
    check = _services()["redis"]["healthcheck"]["test"]
    command = check[-1] if isinstance(check, list) else check
    # The limiter's own user is named too (docs/17 F52's ACL switches `default` off), as
    # an option and not a secret: redis-cli has no variable for the name.
    assert 'REDISCLI_AUTH="$$REDIS_PASSWORD" redis-cli --user noctornal_limiter ping' in command, command
    assert " -a " not in command


@pytest.mark.parametrize("name", ["10-app-role.sh", "20-egress-role.sh"])
def test_the_init_scripts_read_role_passwords_inside_psql_not_from_argv(name):
    text = _text(ROOT / "db" / "init" / name)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert not re.search(r"--set=\w*pw", code), "a role password is a psql argument again"
    assert "\\getenv" in code
    assert re.search(r"\\getenv (apppw|workerpw|egresspw) NOCTORNAL_\w+_PASSWORD", code)


def _dump_schema():
    import importlib.util
    spec = importlib.util.spec_from_file_location("g48_dump_schema", ROOT / "scripts" / "dump_schema.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("url,expect_url,expect_env", [
    ("postgresql://u:p%40ss@h:5432/db", "postgresql://u@h:5432/db", {"PGPASSWORD": "p@ss"}),
    ("postgresql://u:dev_only_change_me@127.0.0.1:5432/noctornal",
     "postgresql://u@127.0.0.1:5432/noctornal", {"PGPASSWORD": "dev_only_change_me"}),
    ("postgresql://u@h/db", "postgresql://u@h/db", {}),
    ("postgresql://h/db", "postgresql://h/db", {}),
])
def test_dump_schema_takes_the_password_out_of_the_url(url, expect_url, expect_env):
    assert _dump_schema().without_password(url) == (expect_url, expect_env)


def test_dump_schema_runs_pg_dump_with_no_password_in_its_arguments(monkeypatch):
    module = _dump_schema()
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"], seen["env"] = cmd, kwargs.get("env") or {}
        return subprocess.CompletedProcess(cmd, 0, stdout=b"CREATE TABLE t ();\n", stderr=b"")

    monkeypatch.setenv("NOCTORNAL_PG_DUMP", "pg_dump")
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module, "current_revision", lambda _url: "0131")
    module.dump("postgresql+psycopg://noctornal:CANARY-pw-7Xq@127.0.0.1:5432/noctornal")
    assert not any("CANARY-pw-7Xq" in part for part in seen["cmd"]), seen["cmd"]
    assert seen["cmd"][-1] == "postgresql://noctornal@127.0.0.1:5432/noctornal"
    assert seen["env"]["PGPASSWORD"] == "CANARY-pw-7Xq"


# --- mc-alias.sh, run ---------------------------------------------------------

def _posix_shell() -> str | None:
    """`sh` on PATH, else the one Git for Windows installs beside git.exe (not
    `bash` from PATH, which on Windows can be WSL's launcher)."""
    found = shutil.which("sh")
    if found:
        return found
    git = shutil.which("git")
    if git:
        root = Path(git).resolve().parent.parent
        for candidate in (root / "bin" / "sh.exe", root / "usr" / "bin" / "sh.exe"):
            if candidate.is_file():
                return str(candidate)
    return None


def _setup(tmp_path: Path, user: str, password: str):
    shell = _posix_shell()
    if shell is None:
        pytest.skip("no POSIX shell")
    cert = tmp_path / "public.crt"
    cert.write_text("CERT", encoding="utf-8")
    script = tmp_path / "run.sh"
    script.write_text('. "$ALIAS_FILE"\nmc_setup || exit 9\nprintf %s "$MC_HOST_local"\n',
                      encoding="utf-8", newline="\n")
    env = {**os.environ, "ALIAS_FILE": (PRODUCTION / "mc-alias.sh").as_posix(),
           "MINIO_ROOT_USER": user, "MINIO_ROOT_PASSWORD": password,
           "MC_CONFIG_DIR": (tmp_path / "mc").as_posix(),
           "MC_CERTIFICATE": cert.as_posix()}
    env.pop("MC_HOST_local", None)
    return subprocess.run([shell, script.as_posix()], capture_output=True, text=True, env=env,
                          timeout=60)


@pytest.mark.parametrize("password", [
    "plain-token_urlsafe-0123456789",
    "p@ss/w rd#1%&+x\"q?=$!~",
    "back\\slash 'single' 100%\tdone",
])
def test_the_alias_carries_the_credential_literally_as_mc_reads_it(tmp_path, password):
    """Measured against the pinned mc: it does not percent-decode an MC_HOST
    value, so an encoded password is the wrong password."""
    done = _setup(tmp_path, "g48-root", password)
    assert done.returncode == 0, done.stderr
    assert done.stdout == f"https://g48-root:{password}@minio:9000"
    assert (tmp_path / "mc" / "certs" / "CAs" / "minio.crt").read_text() == "CERT"


@pytest.mark.parametrize("user,password", [("g48-root", "pass:word-0123"), ("g48:root", "pass-word-0123")])
def test_a_colon_in_the_pair_is_refused_by_name_not_sent_as_another_credential(
        tmp_path, user, password):
    done = _setup(tmp_path, user, password)
    assert done.returncode == 9
    assert "must not contain a colon" in done.stderr
    assert "MINIO_ROOT_PASSWORD" in done.stderr
    assert password not in done.stderr + done.stdout
    assert not (tmp_path / "mc").exists(), "nothing is set up for a pair it will not use"


def test_minio_init_sources_the_alias_file_it_mounts():
    init = _services()["minio-init"]
    assert "./mc-alias.sh:/mc-alias.sh:ro" in init["volumes"]
    script = _script("minio-init", "entrypoint")
    assert script.index(". /mc-alias.sh") < script.index("mc_setup") < script.index("mc ls local")
    assert (PRODUCTION / "mc-alias.sh").is_file()
    assert "mc admin user svcacct add" in script, "the residual is stated in the compose comment"


#: A stand-in for `mc` that behaves as the real client does at the two calls
#: that matter: `svcacct info` finds no account (so the script creates it), and
#: `svcacct add` prints the new account's keys on STDOUT, as the real one does
#: ("Access Key: ..." and "Secret Key: ..."), with a warning on stderr. With
#: STUB_ADD_FAILS it refuses on stderr and exits 1 instead.
_MC_STUB = r"""
mc_setup() { :; }
mc() {
  case "$1 $2 $3 $4" in
    "admin user svcacct info") return 1 ;;
    "admin user svcacct add")
      if [ -n "${STUB_ADD_FAILS:-}" ]; then echo "mc: <ERROR> stub refused the account." >&2; return 1; fi
      shift 4
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --access-key) echo "Access Key: $2"; shift ;;
          --secret-key) echo "Secret Key: $2"; shift ;;
        esac
        shift
      done
      echo "mc: stub stderr line" >&2
      return 0 ;;
  esac
  return 0
}
"""


def _run_minio_init(tmp_path: Path, **extra: str):
    shell = _posix_shell()
    if shell is None:
        pytest.skip("no POSIX shell")
    script = _script("minio-init", "entrypoint")
    assert script.count(". /mc-alias.sh") == 1
    # The alias file is mounted at /mc-alias.sh in the container and is not on
    # this host; the stub defines `mc_setup` where it would have been sourced.
    body = script.replace(". /mc-alias.sh", ":", 1)
    path = tmp_path / "minio-init.sh"
    path.write_text(_MC_STUB + body + "\n", encoding="utf-8", newline="\n")
    env = {**os.environ, "MINIO_ROOT_USER": "test-root", "EVIDENCE_BUCKET": "ev", "INGEST_BUCKET": "in",
           "SAMPLE_BUCKET": "smp", "PRESERVE_BUCKET": "pres",
           "SAMPLE_ACCESS_KEY": "test-sample-ak", "SAMPLE_SECRET_KEY": "TEST-SAMPLE-SECRET-q9Zx",
           "PRESERVE_ACCESS_KEY": "test-pres-ak", "PRESERVE_SECRET_KEY": "TEST-PRESERVE-SECRET-w3Lm", **extra}
    return subprocess.run([shell, path.as_posix()], capture_output=True, text=True, env=env, timeout=60)


def test_minio_init_does_not_print_the_new_accounts_secret_key_into_its_log(tmp_path):
    """`mc admin user svcacct add` echoes the account's secret key on stdout, so
    the first run left it in `docker logs minio-init` for as long as the
    container existed (2026-10-07). Both accounts, the
    sample one and the preserve one, are created with stdout discarded; stderr
    stays, so a warning still reaches the log."""
    done = _run_minio_init(tmp_path)
    assert done.returncode == 0, done.stderr
    seen = done.stdout + done.stderr
    for secret in ("TEST-SAMPLE-SECRET-q9Zx", "TEST-PRESERVE-SECRET-w3Lm"):
        assert secret not in seen, "a secret key reached the container log"
    assert "Secret Key:" not in seen
    assert done.stderr.count("mc: stub stderr line") == 2, "stderr is kept for both accounts"
    assert "buckets ready" in done.stdout


def test_minio_init_still_fails_and_says_why_when_an_account_cannot_be_created(tmp_path):
    done = _run_minio_init(tmp_path, STUB_ADD_FAILS="1")
    assert done.returncode != 0, "set -e must still see a failed svcacct add"
    assert "<ERROR> stub refused the account." in done.stderr
    assert "buckets ready" not in done.stdout


@pytest.mark.parametrize("name, value", [
    ("SAMPLE_SECRET_KEY", "s" * 43),      # token_urlsafe(32), the README's recipe
    ("SAMPLE_ACCESS_KEY", "a" * 21),
    ("PRESERVE_SECRET_KEY", "p" * 7),
    ("PRESERVE_ACCESS_KEY", "q" * 2),
])
def test_minio_init_names_a_service_account_key_minio_would_refuse(tmp_path, name, value):
    """Beta 1 deployment gate (2026-10-07): MinIO takes a service account's
    access key at 3 to 20 characters and its secret key at 8 to 40, and its
    refusal named neither variable. minio-init stops before any account is
    asked for, names the variable and its length, and never prints it."""
    done = _run_minio_init(tmp_path, **{name: value})
    assert done.returncode != 0
    assert f"minio-init: {name} is {len(value)} characters" in done.stderr
    assert "mc: stub stderr line" not in done.stderr, "no account was asked for"
    assert value not in done.stdout + done.stderr
    assert "buckets ready" not in done.stdout


def test_minio_init_accepts_service_account_keys_at_minios_bounds(tmp_path):
    done = _run_minio_init(tmp_path, SAMPLE_ACCESS_KEY="a" * 20, SAMPLE_SECRET_KEY="s" * 40,
                           PRESERVE_ACCESS_KEY="q" * 3, PRESERVE_SECRET_KEY="p" * 8)
    assert done.returncode == 0, done.stderr
    assert "buckets ready" in done.stdout


def test_the_readme_has_the_egress_files_written_before_the_first_up_in_the_image():
    """Beta 1 deployment gate (2026-10-07): followed in order, the README
    reached `up` with no egress files (the API refused, the proxy restarted in
    a loop, `up` exited 1), and its `python scripts/egress_setup.py keygen`
    and `preflight` ran on a host python with none of the application's
    libraries. Step 1 names both files before step 4, and both commands run in
    the image, preflight told the host's Compose version."""
    text = _text(README)
    step1 = text.split("## 1. Write the secrets files", 1)[1].split("## 4. Start it", 1)[0]
    for name in ("egress-proxy.env", "egress-client.env", "collector.env"):
        assert name in step1, name
    assert "compose.yml build" in step1
    keygen = [b for b in _readme_sh_blocks() if "egress_setup.py keygen" in b]
    assert keygen and all("run --rm --no-deps -T api" in b for b in keygen)
    assert "--compose-version \"$(docker compose version --short)\"" in keygen[0]
    assert not re.search(r"(?m)^python3? scripts/egress_setup\.py", "\n".join(_readme_sh_blocks()))


def test_every_svcacct_add_discards_its_stdout_and_keeps_stderr():
    logical = re.sub(r"\\\n\s*", " ", _script("minio-init", "entrypoint")).splitlines()
    # The `info` guard before `||` has its own `>/dev/null 2>&1`; the add is what follows it.
    adds = [line.split("mc admin user svcacct add", 1)[1].strip()
            for line in logical if "mc admin user svcacct add" in line]
    assert len(adds) == 2, "the sample account and the preserve account"
    for line in adds:
        assert line.endswith(">/dev/null"), line
        assert "2>" not in line and "&>" not in line, line


# ---------------------------------------------------------------------------
# infra-11, statically (the loops are run and signalled in test_g48_cron_sigterm.py)
# ---------------------------------------------------------------------------

_LOOPS = ("cron", "lab-triage", "lab-cron", "embed-pass")


def _seconds(value: str) -> int:
    total = 0
    for amount, unit in re.findall(r"(\d+)([hms])", str(value)):
        total += int(amount) * {"h": 3600, "m": 60, "s": 1}[unit]
    return total


@pytest.mark.parametrize("name", _LOOPS)
def test_each_loop_traps_the_stop_signal_and_is_given_time_to_finish_a_pass(name):
    service = _services()[name]
    assert _seconds(service["stop_grace_period"]) >= 330, "a pass has a 240 second budget"
    script = _script(name, "command")
    assert "trap 'stop=1' TERM INT" in script
    assert "while true" not in script and 'while [ -z "$stop" ]; do' in script
    # A plain sleep ignores the signal until it ends; only `nap` (a wait) is interrupted.
    code = [line.strip() for line in script.splitlines() if not line.strip().startswith("#")]
    assert not any(line.startswith("sleep ") for line in code), code
    assert 'nap() { sleep "$1" & wait "$!"; }' in code


@pytest.mark.parametrize("name", _LOOPS)
def test_each_loop_stops_between_steps_not_only_between_passes(name):
    code = [line.strip() for line in _script(name, "command").splitlines()
            if line.strip() and not line.strip().startswith("#")]
    jobs = [i for i, line in enumerate(code) if line.startswith("python scripts/")]
    assert jobs
    for i in jobs:
        assert '[ -z "$stop" ] || break' in code[i + 1:i + 3], (name, code[i])
    naps = [i for i, line in enumerate(code) if line.startswith("nap ")]
    for i in naps[:-1]:
        assert '[ -z "$stop" ] || break' in code[i + 1:i + 2], (name, code[i])
    assert code[-1].endswith('stopped on request"')


# ---------------------------------------------------------------------------
# 2026-10-03: the README's umask, the modes the
# capability-less containers read, and the ignore lists in both directions
# ---------------------------------------------------------------------------

def _readme_sh_blocks() -> list[str]:
    return re.findall(r"```sh\n(.*?)```", _text(README), flags=re.S)


def _readme_block(marker: str) -> str:
    found = [b for b in _readme_sh_blocks() if marker in b]
    assert len(found) == 1, (marker, len(found))
    return found[0]


def _scopes(code: str, words: tuple[str, ...]) -> list[tuple[str, str]]:
    """`(word, 'quoted' | 'group' | 'shell')` for every place one of `words`
    stands in a shell block. A word inside a quoted string is a script handed
    to another shell (`sh -c '...'`), and one inside `( ... )` runs in a
    subshell; only `shell` changes the operator's own session."""
    out: list[tuple[str, str]] = []
    depth, quote, i = 0, None, 0
    while i < len(code):
        ch = code[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or code[i - 1] in " \t\n"):
            i = code.find("\n", i)
            if i < 0:
                break
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if code.startswith(words, i) and (i == 0 or code[i - 1] in " \t\n(;'\""):
            word = next(w for w in words if code.startswith(w, i))
            out.append((word, "quoted" if quote else "group" if depth > 0 else "shell"))
            i += len(word)
            continue
        i += 1
    return out


def test_scope_reader_tells_a_subshell_from_the_operators_own_shell():
    assert _scopes("umask 077\ncp a b\n", ("umask 077",)) == [("umask 077", "shell")]
    assert _scopes("( umask 077\n  cp a b )\n", ("umask 077",)) == [("umask 077", "group")]
    assert _scopes("x -c '\n  umask 077\n'\n", ("umask 077",)) == [("umask 077", "quoted")]
    assert _scopes("# umask 077 in a comment\n", ("umask 077",)) == []
    assert _scopes("(\n  set -o pipefail\n)\nset -o pipefail\n", ("set -o pipefail",)) == [
        ("set -o pipefail", "group"), ("set -o pipefail", "shell")]


def test_no_readme_command_leaves_a_umask_or_shell_option_in_the_operators_shell():
    """README step 1, the egress block and the backup block each ran
    `umask 077` as a bare line in the operator's shell. Step 3 then made
    `tls/` 0700 and `public.crt` 0600 under it: the application (uid 10001)
    and MinIO (root, no DAC_OVERRIDE) could not read the certificate, and a
    `git pull` in that shell wrote 0600 files the image copied with their
    modes (2026-10-03). Scoped, the setting ends with the
    command that needed it."""
    seen: list[tuple[str, str]] = []
    for block in _readme_sh_blocks():
        seen += _scopes(block, ("umask 077", "set -o pipefail", "set -e", "set -u"))
    assert [s for s in seen if s[0] == "umask 077"], "the README no longer sets a umask at all"
    leaking = [s for s in seen if s[1] == "shell"]
    assert not leaking, f"these outlive their command in the operator's shell: {leaking}"
    # Not vacuous: the three host-side blocks and the container script are all seen.
    assert sorted(scope for word, scope in seen if word == "umask 077") == [
        "group", "group", "group", "quoted"]


def test_the_readme_commands_for_the_tls_directory_state_modes_instead_of_trusting_umask():
    block = _readme_block("mkdir -p infra/production/tls")
    assert "chmod 755 infra/production/tls\n" in block
    assert "chmod 644 infra/production/tls/public.crt\n" in block
    assert block.index("openssl req") < block.index("chmod 755")
    assert "sudo chown root:root infra/production/tls/private.key" in block
    assert "sudo chmod 600       infra/production/tls/private.key" in block


def test_the_readme_checks_the_modes_the_containers_read_before_up():
    text = _text(README)
    step = text[text.index("## 4. Start it"):text.index("### If the API refuses to start")]
    assert step.index("find infra/production/Caddyfile") < step.index("up -d --build")
    for path in ("infra/production/Caddyfile", "infra/production/mc-alias.sh",
                 "infra/production/tls", "db/init"):
        assert path in step.split("up -d --build")[0], path
    assert "chmod go+rX" in step
    # The bind mounts that need it are exactly the ones the compose file declares.
    mounts = set()
    for service in _services().values():
        for volume in service.get("volumes", []) or []:
            source = str(volume).split(":")[0]
            if source.startswith("."):
                mounts.add(os.path.normpath(os.path.join("infra/production", source)).replace("\\", "/"))
    assert mounts == {"infra/production/tls", "infra/production/Caddyfile", "db/init",
                      "infra/production/mc-alias.sh"}, mounts


@pytest.mark.parametrize("marker", ["secrets.env.example", "egress_setup.py keygen",
                                    "mkdir -p infra/production/tls", "set -o pipefail",
                                    "find infra/production/Caddyfile"])
def test_every_readme_block_that_changes_modes_is_valid_shell(marker):
    bash = _bash_for_syntax()
    if bash is None:
        pytest.skip("no bash")
    done = subprocess.run([bash, "-n"], input=_readme_block(marker), capture_output=True,
                          text=True, timeout=30)
    assert done.returncode == 0, done.stderr


def _bash_for_syntax() -> str | None:
    found = shutil.which("bash")
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            here = Path(git).resolve()
            for root in (here.parent.parent, here.parent.parent.parent):
                for rel in ("bin/bash.exe", "usr/bin/bash.exe"):
                    if (root / rel).is_file():
                        return str(root / rel)
        return None
    return found


_POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="file modes and umask need POSIX")


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _run_readme_blocks(tmp_path: Path, operator_umask: str):
    """Run the README's host-side blocks in ONE bash session, in the order an
    operator does, with the tools that need a stack stubbed, and report the
    session's umask after each block."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash")
    tree = tmp_path / "checkout"
    (tree / "infra" / "production").mkdir(parents=True)
    for template in PRODUCTION.glob("*.example"):
        copied = tree / "infra" / "production" / template.name
        shutil.copy(template, copied)
        copied.chmod(0o644)       # git's mode for a template, whatever this checkout's filesystem says
    backup = tmp_path / "backup"
    blocks = [
        ("secrets", _readme_block("secrets.env.example")),
        ("egress", _readme_block("egress_setup.py keygen")),
        ("tls", _readme_block("mkdir -p infra/production/tls")),
        ("backup", _readme_block("set -o pipefail").replace("/srv/noctornal-backup", str(backup))),
    ]
    script = [
        f"umask {operator_umask}", 'cd "$1"',
        "sudo() { \"$@\"; }; chown() { :; }",     # the operator is not root here
        # Step 1's last command, the installer step, creates the two files only it knows
        # (docs/17 F52) from their templates, private; scripts/production_secrets.py does it
        # for real and test_production_secrets_script.py holds that. Here it is a stand-in.
        "installer() { ( umask 077; for f in postgres-init migrate; do [ -f infra/production/$f.env ]"
        " || cp infra/production/$f.env.example infra/production/$f.env; done ); }",
        "sudo() { if [ \"$1\" = ./release/install.sh ]; then installer; else \"$@\"; fi; }",
        "python() { :; }; docker() { echo stub-dump; }; age() { cat; }",
        # openssl creates the key 0600 whatever the umask and the certificate
        # under the umask: that is the difference this test needs to keep.
        "openssl() { while [ $# -gt 0 ]; do case \"$1\" in -keyout) k=\"$2\"; shift;; -out) c=\"$2\"; shift;; esac; shift; done;"
        " ( umask 077; echo KEY > \"$k\" ); echo CERT > \"$c\"; }",
    ]
    for name, block in blocks:
        script.append(f"# ---- {name}\n{block}")
        script.append(f'echo "after-{name}: $(umask)"')
    path = tmp_path / "operator.sh"
    path.write_text("\n".join(script) + "\n", encoding="utf-8", newline="\n")
    done = subprocess.run([bash, path.as_posix(), tree.as_posix()], capture_output=True,
                          text=True, timeout=120)
    return done, tree, backup


@_POSIX_ONLY
@pytest.mark.parametrize("operator_umask", ["0022", "0077"])
def test_after_the_readme_commands_the_operators_umask_is_what_it_was(tmp_path, operator_umask):
    done, _tree, _backup = _run_readme_blocks(tmp_path, operator_umask)
    assert done.returncode == 0, done.stdout + done.stderr
    after = re.findall(r"after-\w+: (\d+)", done.stdout)
    assert len(after) == 4 and set(after) == {operator_umask}, done.stdout


@_POSIX_ONLY
@pytest.mark.parametrize("operator_umask", ["0022", "0077"])
def test_the_modes_the_containers_need_hold_under_either_umask(tmp_path, operator_umask):
    """The directory and certificate are readable by `other` even on a host
    whose own umask is 077, the secrets are private from the first byte even
    on one whose umask is 022, and the backup directory and dump are private."""
    done, tree, backup = _run_readme_blocks(tmp_path, operator_umask)
    assert done.returncode == 0, done.stdout + done.stderr
    prod = tree / "infra" / "production"
    assert (_mode(prod / "secrets.env"), _mode(prod / "caddy.env")) == (0o600, 0o600)
    for name in ("egress-proxy.env", "egress-client.env", "postgres-init.env", "migrate.env"):
        assert _mode(prod / name) == 0o600, name
    assert _mode(prod / "tls") == 0o755
    assert _mode(prod / "tls" / "public.crt") == 0o644
    assert _mode(prod / "tls" / "private.key") == 0o600
    assert _mode(backup) == 0o700
    dumps = list(backup.glob("noctornal-*.dump.age"))
    assert len(dumps) == 1 and _mode(dumps[0]) == 0o600


@_POSIX_ONLY
def test_the_mode_check_names_what_a_container_could_not_read(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash")
    check = _readme_block("find infra/production/Caddyfile").strip()
    prod = tmp_path / "infra" / "production"
    for directory in (prod / "tls", tmp_path / "db" / "init"):
        directory.mkdir(parents=True)
    files = {prod / "Caddyfile": 0o644, prod / "mc-alias.sh": 0o644, prod / "tls" / "public.crt": 0o644,
             prod / "tls" / "private.key": 0o600, tmp_path / "db" / "init" / "10-app-role.sh": 0o644}
    for path, mode in files.items():
        path.write_text("x", encoding="utf-8")
        path.chmod(mode)
    for directory in (prod / "tls", tmp_path / "db" / "init"):
        directory.chmod(0o755)

    def run() -> list[str]:
        done = subprocess.run([bash, "-c", check], cwd=tmp_path, capture_output=True, text=True,
                              timeout=30)
        assert done.returncode == 0, done.stderr
        return sorted(done.stdout.split())

    assert run() == [], "a correct tree is named as wrong (private.key is skipped on purpose)"
    (prod / "Caddyfile").chmod(0o600)
    (prod / "tls").chmod(0o700)
    (tmp_path / "db" / "init" / "10-app-role.sh").chmod(0o640)
    assert run() == ["db/init/10-app-role.sh", "infra/production/Caddyfile", "infra/production/tls"]


def _dockerfile_normalisation() -> str:
    text = _text(ROOT / "Dockerfile")
    match = re.search(r"&& (find /app [^\n]*)", text)
    assert match, "the Dockerfile no longer makes what it copies readable"
    return match.group(1)


def test_the_image_makes_what_it_copies_readable_before_it_drops_privileges():
    text = _text(ROOT / "Dockerfile")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    command = _dockerfile_normalisation()
    assert command == r"find /app \( -type f ! -perm -o=r -o -type d ! -perm -o=rx \) -exec chmod go+rX {} +"
    assert code.index("COPY . /app") < code.index(command) < code.index("USER 10001:10001")
    # In the pip step's own RUN, so a normal context adds no layer.
    run = code[code.rindex("RUN ", 0, code.index(command)):code.index(command)]
    assert "pip install" in run


@_POSIX_ONLY
def test_the_normalising_command_opens_a_restrictive_checkout_and_leaves_the_rest(tmp_path):
    """A COPY of a tree made under umask 077 is 0600 files in 0700 directories:
    uid 10001 reads none of it. The command opens exactly those, keeps an
    executable executable, and does not touch what was already readable."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash")
    app = tmp_path / "app"
    (app / "scripts").mkdir(parents=True)
    (app / "open").mkdir()
    layout = {app / "scripts" / "run.py": 0o600, app / "scripts" / "tool.sh": 0o700,
              app / "open" / "fine.py": 0o644, app / "open" / "fine.sh": 0o755,
              app / "top.toml": 0o600}
    for path, mode in layout.items():
        path.write_text("x", encoding="utf-8")
        path.chmod(mode)
    app.chmod(0o700)
    (app / "scripts").chmod(0o700)
    (app / "open").chmod(0o755)
    before = {p: p.stat().st_ctime_ns for p in (app / "open", app / "open" / "fine.py")}
    done = subprocess.run([bash, "-c", _dockerfile_normalisation().replace("/app", app.as_posix())],
                          capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    assert [_mode(p) for p in (app, app / "scripts")] == [0o755, 0o755]
    assert _mode(app / "scripts" / "run.py") == 0o644 and _mode(app / "top.toml") == 0o644
    assert _mode(app / "scripts" / "tool.sh") == 0o755, "an executable stays executable"
    assert _mode(app / "open" / "fine.sh") == 0o755 and _mode(app / "open" / "fine.py") == 0o644
    assert {p: p.stat().st_ctime_ns for p in before} == before, "an already readable path was rewritten"


# --- the ignore lists, held to each other in both directions ----------------

_DIRECTORIES = ("", "apps/api/", "infra/production/", "a/b/c/")
#: Names that hold, or are a copy of something that holds, a secret.
_SECRET_NAMES = (".env", ".env.local", ".env.production", "secrets.env", "migrate.env",
                 "secrets.env.bak", "secrets.env~", "secrets.env.old", "secrets.env.orig",
                 "secrets-prod.env.save", "prod.env.save", "caddy.env.swp")
_TEMPLATES = ("secrets.env.example", "caddy.env.example", "egress-proxy.env.example")


def test_the_image_context_refuses_a_secret_file_at_any_depth_and_an_editors_copy_of_one():
    """`.env` and `.env.*` were root-anchored here and match at any depth in
    .gitignore, so apps/api/.env.local and infra/production/.env.production
    were gitignored yet reached every image, and `secrets.env.bak`,
    `secrets.env~` and the like were in neither list."""
    ignore = Dockerignore(_text(ROOT / ".dockerignore"))
    reached = [d + n for d in _DIRECTORIES for n in _SECRET_NAMES if not ignore.excluded(d + n)]
    assert not reached, f"these would be copied into the image: {reached}"


def test_git_refuses_every_secret_file_the_image_context_refuses():
    """The reverse direction: `infra/production/*.env` existed in .dockerignore
    only, so a future migrate.env was kept out of the image and staged by
    `git add -A`."""
    paths = [d + n for d in _DIRECTORIES for n in _SECRET_NAMES]
    if _git_ignored(paths[0]) is None:
        pytest.skip("not a git checkout")
    staged = [p for p in paths if not _git_ignored(p)]
    assert not staged, f"`git add -A` would stage these: {staged}"


def test_the_templates_are_neither_ignored_by_git_nor_kept_out_of_the_image():
    ignore = Dockerignore(_text(ROOT / ".dockerignore"))
    for directory in _DIRECTORIES:
        for name in _TEMPLATES:
            assert not ignore.excluded(directory + name), directory + name
    if _git_ignored("infra/production/secrets.env.example") is None:
        pytest.skip("not a git checkout")
    for directory in _DIRECTORIES:
        for name in _TEMPLATES:
            assert _git_ignored(directory + name) is False, directory + name
    # A bare `.env.example` stays refused by both, as `.env.*` always made it.
    assert Dockerignore(_text(ROOT / ".dockerignore")).excluded(".env.example")
    assert _git_ignored(".env.example") is True


@pytest.mark.parametrize("name", ["Caddyfile.bak", "notes.orig", "x.old", "x.save", "x.swp",
                                  "a/b/c~", "infra/production/secrets.env~"])
def test_an_editors_copy_of_any_file_stays_out_of_the_image_and_out_of_git(name):
    assert Dockerignore(_text(ROOT / ".dockerignore")).excluded(name)
    ignored = _git_ignored(name)
    if ignored is None:
        pytest.skip("not a git checkout")
    assert ignored, name


def test_no_tracked_file_is_hidden_by_the_wider_ignore_rules():
    """The wider rules must not take a file the repository tracks or the
    image needs: nothing tracked ends in `.env`, `~`, `.bak`, `.orig`,
    `.old`, `.save` or `.swp`, apart from the `.example` templates."""
    if shutil.which("git") is None:
        pytest.skip("no git")
    listed = subprocess.run(["git", "ls-files", "-ci", "--exclude-standard"], cwd=ROOT,
                            capture_output=True, text=True)
    if listed.returncode != 0:
        pytest.skip("not a git checkout")
    assert listed.stdout.split() == [], listed.stdout
    ignore = Dockerignore(_text(ROOT / ".dockerignore"))
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout
    wider = re.compile(r"(\.env(\.|$)|~$|\.(bak|orig|old|save|swp)$)")
    hidden = [p for p in tracked.split("\n")
              if p and wider.search(p) and not p.endswith(".env.example") and ignore.excluded(p)]
    assert hidden == [], hidden


# --- the owner role: wording that matches the boot refusal, and a way out ----

def test_no_template_or_script_still_calls_connecting_as_the_owner_a_silent_supported_state():
    """infra-4 made a production boot refuse a DATABASE_URL naming the owner
    or a superuser, but the template's comment still said the deployment
    'works' there 'silently', and the init script printed 'This deployment
    will connect as the owner' (2026-10-03)."""
    template = _text(PRODUCTION / "secrets.env.example")
    comment = template[template.index("# What the API, the sample origin and the cron loop connect as."):
                       template.index("\nDATABASE_URL=")]
    assert "silently" not in comment and "whole point of the split is gone" not in comment
    assert "production refuses to" in comment.replace("\n# ", " ")
    assert "step 2 of" in comment.replace("\n# ", " ") and "README.md" in comment
    init = _text(ROOT / "db" / "init" / "10-app-role.sh")
    assert "This deployment will connect as the owner" not in init
    assert "supported outcome for DEVELOPMENT" in init
    echoed = "\n".join(line for line in init.splitlines() if line.lstrip().startswith("echo "))
    assert "A development stack connects as the owner" in echoed
    assert "A production deployment refuses to" in echoed
    assert "runtime_roles.py ensure --production" in echoed


def test_the_readme_says_how_to_get_the_app_role_on_a_volume_that_was_initialised_without_it():
    text = _text(README)
    step = text[text.index("## 2. Check the two passwords"):text.index("## 3. Give MinIO a certificate")]
    assert "initialised without that password has no `noctornal_app`" in step
    block = next(b for b in re.findall(r"```sh\n(.*?)```", step, flags=re.S) if "runtime_roles.py" in b)
    assert "scripts/runtime_roles.py ensure --production" in block
    assert "\\password noctornal_app" in block and "\\password noctornal_worker" in block
    # The password is typed at a prompt, never an argument.
    assert "PASSWORD '" not in block and "--password" not in block
    # It runs in the service compose already gives the owner DSN to, the same way that service does:
    # the migrate service swaps the owner's DSN in as DATABASE_URL in a script now (docs/17 F52,
    # scripts/migrate_job.py, which also refuses before it connects), where it was a line of shell.
    migrate = _script("migrate", "command")
    assert migrate == "scripts/migrate_job.py"
    assert 'env["DATABASE_URL"] = dsn' in _text(ROOT / "scripts" / "migrate_job.py")
    assert 'DATABASE_URL="$NOCTORNAL_MIGRATION_DATABASE_URL" python scripts/runtime_roles.py' in block
    assert {"migrate", "postgres"} <= set(_services())
    assert "--production" in _text(ROOT / "scripts" / "runtime_roles.py")


# --- infra-7's residual, with the digests in the repository -------------------

def _tag_only_images() -> dict[str, str]:
    """image -> where, for every image the development stack and CI pull by tag."""
    found: dict[str, str] = {}
    for path in (DEV_COMPOSE, ROOT / ".github" / "workflows" / "ci.yml"):
        for image in re.findall(r"(?m)^\s+image:\s*(\S+)\s*$", _text(path)):
            assert "@sha256:" not in image, f"{image} in {path.name} is pinned now: update this test"
            found.setdefault(image, path.name)
    return found


def _readme_digest_table() -> dict[str, str]:
    text = _text(README)
    section = text[text.index("**Images and tools that are not digest pinned.**"):text.index("\n---\n", text.index(
        "**Images and tools that are not digest pinned.**"))]
    return {m.group(1): m.group(2)
            for m in re.finditer(r"\| `([^`]+)` \| [^|\n]+ \| `(sha256:[0-9a-f]{64})` \|", section)}


def test_every_image_pulled_by_tag_is_named_in_the_readme_with_the_digest_it_resolved_to():
    table = _readme_digest_table()
    pulled = _tag_only_images()
    assert {"pgvector/pgvector:pg16", "redis:7-alpine", "axllent/mailpit:v1.31.0"} <= set(pulled), pulled
    missing = sorted(set(pulled) - set(table))
    assert not missing, f"README Hardening does not list these tag-only images with a digest: {missing}"


def test_the_readme_digests_are_the_ones_the_production_stack_pins():
    """A tag shared with production must carry production's digest, so a pin
    moved in compose.yml without the table fails here instead of going stale."""
    table = _readme_digest_table()
    pinned = {}
    for service in _services().values():
        image = service.get("image", "")
        if "@sha256:" in image:
            name, digest = image.split("@")
            pinned[name] = digest
    shared = sorted(set(table) & set(pinned))
    assert {"pgvector/pgvector:pg16", "redis:7-alpine"} <= set(shared), shared
    assert {name for name in pinned if name.startswith("ghcr.io/dboudreau00/")} <= set(shared)
    wrong = {name: (table[name], pinned[name]) for name in shared if table[name] != pinned[name]}
    assert not wrong, wrong
