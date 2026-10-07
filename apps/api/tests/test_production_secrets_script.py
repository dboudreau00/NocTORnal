"""scripts/production_secrets.py, and the installer switches that run it
(docs/17 F52 and the limiter's Redis ACL, 2026-10-02).

Moving the schema owner's credential out of secrets.env naively would stop
every existing production deployment at boot, so the installers bring an
existing deployment along: they detect the old layout, move the values
into the files that now hold them with restrictive permissions and a backup
of each file they change, and write the Redis password and a REDIS_URL that
signs in as the limiter's own user. Held here, against temporary
directories only:

* an old-layout deployment is moved, value for value, with backups, and the
  result is one the API, the migration job and the redis service accept;
* a second run changes nothing; a conflict writes nothing;
* a fresh deployment gets its Redis password, and its owner password only
  when the database volume does not exist yet;
* nothing printed carries a value;
* install.sh --production-secrets runs the same helper as install.ps1
  -ProductionSecrets. The PowerShell run exists on Windows only; what is
  held about install.ps1 everywhere is its text (no test here skips: CI's
  "No tests were skipped" gate fails the build on one).
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from acl_redis_support import posix_shell, run_start_script
from noctornal_api import config
from noctornal_api.ratelimit_redis import LIMITER_ACL_USER

ROOT = Path(__file__).resolve().parents[3]
PROD = ROOT / "infra" / "production"
HELPER = ROOT / "scripts" / "production_secrets.py"
STAMP = "20261002T120000Z"

OWNER = "Ow7-owner-pass"
APP = "App9-app-pass"
REDIS = "Rd3-redis-pass"
EGRESS = "Eg5-egress-pass"
WORKER = "Wk6-worker-pass"
VALUES = (OWNER, APP, REDIS, EGRESS, WORKER)

OLD_SECRETS = f"""# an older secrets.env
POSTGRES_PASSWORD={OWNER}
NOCTORNAL_APP_DB_PASSWORD={APP}
NOCTORNAL_MIGRATION_DATABASE_URL=postgresql+psycopg://noctornal:{OWNER}@postgres:5432/noctornal
DATABASE_URL=postgresql+psycopg://noctornal_app:{APP}@postgres:5432/noctornal
REDIS_PASSWORD={REDIS}
REDIS_URL=redis://:{REDIS}@redis:6379/0
NOCTORNAL_ENV=production
"""
OLD_INIT = f"""# the egress era's postgres-init.env
NOCTORNAL_EGRESS_DB_PASSWORD={EGRESS}
NOCTORNAL_WORKER_DB_PASSWORD={WORKER}
"""


def _helper():
    spec = importlib.util.spec_from_file_location("production_secrets", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def prod(tmp_path):
    """A production directory holding the templates, as a checkout does."""
    for name in ("secrets.env.example", "postgres-init.env.example", "migrate.env.example"):
        shutil.copy(PROD / name, tmp_path / name)
    return tmp_path


def _env(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def _run(directory, **kwargs):
    said = []
    status = _helper().apply(directory, out=said.append, stamp=STAMP, **kwargs)
    for line in said:
        for value in VALUES:
            assert value not in line, f"a value was printed: {line!r}"
    return status, said


def _old_layout(prod: Path) -> Path:
    (prod / "secrets.env").write_text(OLD_SECRETS, encoding="utf-8")
    (prod / "postgres-init.env").write_text(OLD_INIT, encoding="utf-8")
    return prod


# ---------------------------------------------------------------------------
# An existing deployment
# ---------------------------------------------------------------------------

def test_an_old_layout_is_moved_value_for_value(prod):
    status, said = _run(_old_layout(prod))
    assert status == 0, said
    secrets, init, migrate = (_env(prod / n) for n in
                              ("secrets.env", "postgres-init.env", "migrate.env"))
    assert config.OWNER_PASSWORD_ENV not in secrets
    assert config.MIGRATION_DSN_ENV not in secrets
    assert init[config.OWNER_PASSWORD_ENV] == OWNER
    assert migrate[config.MIGRATION_DSN_ENV] == \
        f"postgresql+psycopg://noctornal:{OWNER}@postgres:5432/noctornal"
    # Everything else stays exactly as it was.
    assert init["NOCTORNAL_EGRESS_DB_PASSWORD"] == EGRESS
    assert init["NOCTORNAL_WORKER_DB_PASSWORD"] == WORKER
    assert secrets["DATABASE_URL"].endswith(f":{APP}@postgres:5432/noctornal")
    assert secrets["REDIS_PASSWORD"] == REDIS
    assert secrets["REDIS_URL"] == f"redis://{LIMITER_ACL_USER}:{REDIS}@redis:6379/0"
    text = (prod / "secrets.env").read_text(encoding="utf-8")
    assert "# POSTGRES_PASSWORD moved to postgres-init.env (docs/17 F52" in text
    assert "moved POSTGRES_PASSWORD from secrets.env to postgres-init.env" in said
    assert f"REDIS_URL now signs in as {LIMITER_ACL_USER} with REDIS_PASSWORD" in said


def test_every_changed_file_is_backed_up_first_and_the_new_files_are_private(prod):
    _old_layout(prod)
    before = {n: (prod / n).read_bytes() for n in ("secrets.env", "postgres-init.env")}
    status, said = _run(prod)
    for name, original in before.items():
        backup = prod / f"{name}.backup-{STAMP}"
        assert backup.read_bytes() == original, name
        assert f"backed up {name} to {backup.name} (mode 600)" in said
    assert not (prod / f"migrate.env.backup-{STAMP}").exists(), "it did not exist before"
    assert "created migrate.env from migrate.env.example (mode 600)" in said
    if os.name == "posix":
        for name in ("secrets.env", "postgres-init.env", "migrate.env",
                     f"secrets.env.backup-{STAMP}", f"postgres-init.env.backup-{STAMP}"):
            assert (prod / name).stat().st_mode & 0o777 == 0o600, name
    assert not list(prod.glob(".*.tmp-*")), "a temporary file was left behind"


def test_the_moved_files_are_ones_every_reader_accepts(prod):
    """The API (no owner credential), the migration job (its DSN, no
    published value) and the redis service's start check (REDIS_URL signs
    in as the limiter with REDIS_PASSWORD) all accept the result."""
    _run(_old_layout(prod))
    secrets = _env(prod / "secrets.env")
    assert config.owner_credential_problems(secrets) == []
    migrate = {"NOCTORNAL_ENV": "production", **_env(prod / "migrate.env")}
    assert config.migration_job_problems(migrate) == []
    assert secrets["REDIS_URL"].startswith(
        f"redis://{LIMITER_ACL_USER}:{secrets['REDIS_PASSWORD']}@")


def test_a_second_run_changes_nothing(prod):
    _run(_old_layout(prod))
    after = {p.name: p.read_bytes() for p in prod.iterdir()}
    status, said = _run(prod)
    assert status == 0
    assert said == ["nothing to change: the files are already in this release's layout"]
    assert {p.name: p.read_bytes() for p in prod.iterdir()} == after


def test_a_different_owner_password_already_in_place_writes_nothing(prod):
    _old_layout(prod)
    (prod / "postgres-init.env").write_text(OLD_INIT + "POSTGRES_PASSWORD=Other1-pass\n",
                                            encoding="utf-8")
    before = {p.name: p.read_bytes() for p in prod.iterdir()}
    status, said = _run(prod)
    assert status == 1
    assert said[0].startswith("refused: POSTGRES_PASSWORD is in both secrets.env and "
                              "postgres-init.env, with different values.")
    assert said[0].endswith("Nothing was written.")
    assert {p.name: p.read_bytes() for p in prod.iterdir()} == before
    assert "Other1" not in said[0]


def test_the_same_value_in_both_places_is_not_a_conflict(prod):
    _old_layout(prod)
    (prod / "postgres-init.env").write_text(OLD_INIT + f'POSTGRES_PASSWORD="{OWNER}"\n',
                                            encoding="utf-8")
    status, _ = _run(prod)
    assert status == 0
    assert config.OWNER_PASSWORD_ENV not in _env(prod / "secrets.env")


def test_a_placeholder_left_in_secrets_env_is_dropped_not_moved(prod):
    _old_layout(prod)
    text = OLD_SECRETS.replace(f"POSTGRES_PASSWORD={OWNER}",
                               "POSTGRES_PASSWORD=replace-me-owner-password")
    (prod / "secrets.env").write_text(text, encoding="utf-8")
    (prod / "postgres-init.env").write_text(OLD_INIT + f"POSTGRES_PASSWORD={OWNER}\n",
                                            encoding="utf-8")
    status, said = _run(prod)
    assert status == 0, said
    assert _env(prod / "postgres-init.env")[config.OWNER_PASSWORD_ENV] == OWNER
    assert any(s.startswith("removed the placeholder POSTGRES_PASSWORD") for s in said)


def test_a_key_set_twice_is_refused(prod):
    _old_layout(prod)
    with (prod / "secrets.env").open("a", encoding="utf-8") as fh:
        fh.write("REDIS_URL=redis://:second@redis:6379/0\n")
    status, said = _run(prod)
    assert status == 1 and "REDIS_URL is set 2 times in secrets.env" in said[0]
    assert not list(prod.glob("*.backup-*"))


def test_crlf_line_endings_survive(prod):
    _old_layout(prod)
    (prod / "secrets.env").write_bytes(OLD_SECRETS.replace("\n", "\r\n").encode())
    _run(prod)
    raw = (prod / "secrets.env").read_bytes()
    assert b"\r\n" in raw and raw.count(b"\n") == raw.count(b"\r\n")


def test_the_owner_dsn_and_password_disagreeing_is_left_for_the_operator(prod):
    (prod / "secrets.env").write_text(f"REDIS_PASSWORD={REDIS}\n", encoding="utf-8")
    (prod / "postgres-init.env").write_text(f"POSTGRES_PASSWORD={OWNER}\n", encoding="utf-8")
    (prod / "migrate.env").write_text(
        "NOCTORNAL_MIGRATION_DATABASE_URL=postgresql+psycopg://noctornal:"
        "Zz1-other@postgres:5432/noctornal\n", encoding="utf-8")
    status, said = _run(prod)
    assert status == 1
    assert any(s.startswith("still to do: the password inside NOCTORNAL_MIGRATION_"
                            "DATABASE_URL (migrate.env) is not POSTGRES_PASSWORD")
               for s in said), said
    assert not any("Zz1" in s for s in said)


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------

def test_a_password_that_is_not_url_safe_is_replaced(prod):
    _old_layout(prod)
    text = OLD_SECRETS.replace(f"REDIS_PASSWORD={REDIS}", "REDIS_PASSWORD=p@ss:w/rd")
    (prod / "secrets.env").write_text(text, encoding="utf-8")
    status, said = _run(prod)
    secrets = _env(prod / "secrets.env")
    assert secrets["REDIS_PASSWORD"] != "p@ss:w/rd"
    assert _helper().URL_SAFE.match(secrets["REDIS_PASSWORD"])
    assert secrets["REDIS_URL"] == \
        f"redis://{LIMITER_ACL_USER}:{secrets['REDIS_PASSWORD']}@redis:6379/0"
    assert "generated REDIS_PASSWORD (it was not URL-safe)" in said
    assert not any("p@ss" in s for s in said)


def test_a_url_that_disagreed_with_the_password_is_made_to_agree(prod):
    _old_layout(prod)
    text = OLD_SECRETS.replace(f"REDIS_URL=redis://:{REDIS}@", "REDIS_URL=redis://:stale@")
    (prod / "secrets.env").write_text(text, encoding="utf-8")
    _run(prod)
    assert _env(prod / "secrets.env")["REDIS_URL"] == \
        f"redis://{LIMITER_ACL_USER}:{REDIS}@redis:6379/0"


def test_a_redis_on_another_host_is_left_alone(prod):
    _old_layout(prod)
    text = OLD_SECRETS.replace(f"REDIS_URL=redis://:{REDIS}@redis:6379/0",
                               "REDIS_URL=rediss://cache.example.gov:6380/0")
    (prod / "secrets.env").write_text(text, encoding="utf-8")
    status, said = _run(prod)
    assert status == 0, said
    assert _env(prod / "secrets.env")["REDIS_URL"] == "rediss://cache.example.gov:6380/0"
    assert any(s.startswith("note: REDIS_URL names a Redis on another host, so it was "
                            "left alone") and "how to leave the bundled one out" in s
               for s in said), said


@pytest.mark.skipif(posix_shell() is None, reason="no POSIX sh on this machine")
@pytest.mark.parametrize("url", [
    f"redis://:{REDIS}@redis:6379/0",                    # an older secrets.env
    f"redis://:{REDIS}@REDIS:6379/0",                    # host names have no case
    "redis://redis:6379/0",
    f"rediss://{LIMITER_ACL_USER}:{REDIS}@redis:6379/0",  # left alone until 2026-10-02
    f"redis://other:{REDIS}@redis:6379/0?socket_timeout=1",
    "unix:///run/redis.sock",
    "not a url",
    "",
    "redis://:replace-me-redis-password@redis:6379/0",
    f"redis://cache-user:{REDIS}@cache.corp.example:6380/0",
])
def test_whatever_the_start_check_refuses_the_installer_rewrites(prod, url, tmp_path):
    """No circle (review of 2026-10-02): the redis service's start check
    names this step for every REDIS_URL it refuses, so after this step its
    start check passes, whatever REDIS_URL was. Until then a `rediss://`
    URL naming the bundled service was left alone here and refused there."""
    _old_layout(prod)
    text = OLD_SECRETS.replace(f"REDIS_URL=redis://:{REDIS}@redis:6379/0", f"REDIS_URL={url}")
    (prod / "secrets.env").write_text(text, encoding="utf-8")
    status, said = _run(prod)
    assert status == 0, said
    secrets = _env(prod / "secrets.env")
    code, _out, err, _acl = run_start_script(
        {"REDIS_PASSWORD": secrets["REDIS_PASSWORD"], "REDIS_URL": secrets["REDIS_URL"]},
        tmp_path)
    assert code == 0, err


# ---------------------------------------------------------------------------
# The old template's comments (review of 2026-10-02)
# ---------------------------------------------------------------------------

#: The Postgres and Redis sections of secrets.env.example before 2026-10-02,
#: comments shortened, each keeping the phrase the helper recognises it by.
OLD_TEMPLATE = f"""# ---------------------------------------------------------------------------
# Postgres
# ---------------------------------------------------------------------------
# There are TWO roles on purpose. `noctornal` owns the schema and is the
# only thing that runs Alembic.

# The OWNER role's password, given to the Postgres image at initdb.
# It must be BYTE-IDENTICAL to the password inside
# NOCTORNAL_MIGRATION_DATABASE_URL below. Nothing compares them; a mismatch
# shows up as the migration job failing to authenticate, on first boot.
POSTGRES_PASSWORD={OWNER}

# The APP role's password. Read by the initdb script that creates the role.
NOCTORNAL_APP_DB_PASSWORD={APP}

# What Alembic connects as. Read ONLY by the `migrate` service, which
# exports it over DATABASE_URL for the length of `alembic upgrade head`.
# Host `postgres` is the compose service name.
NOCTORNAL_MIGRATION_DATABASE_URL=postgresql+psycopg://noctornal:{OWNER}@postgres:5432/noctornal

DATABASE_URL=postgresql+psycopg://noctornal_app:{APP}@postgres:5432/noctornal


# ---------------------------------------------------------------------------
# Redis, the rate limiter's meter store
# ---------------------------------------------------------------------------

# What `redis-server --requirepass` is started with. The clients read
# REDIS_URL instead, which spells the same password out again.
REDIS_PASSWORD={REDIS}

# Note the empty username before the colon: `redis://:PASSWORD@host`.
# Unset, the limiter falls back to per-process meters.
REDIS_URL=redis://:{REDIS}@redis:6379/0
NOCTORNAL_ENV=production
"""


def test_the_old_templates_comments_go_with_the_lines_they_described(prod):
    """The verifier's reproduction: an old secrets.env kept "Nothing
    compares them" above the marker of a line that had moved, and
    "--requirepass" and "the empty username" above Redis lines that now
    say the opposite."""
    (prod / "secrets.env").write_text(OLD_TEMPLATE, encoding="utf-8")
    (prod / "postgres-init.env").write_text(OLD_INIT, encoding="utf-8")
    status, said = _run(prod)
    assert status == 0, said
    text = (prod / "secrets.env").read_text(encoding="utf-8")
    for phrase in _helper().STALE_COMMENTS.values():
        assert phrase not in text, phrase
    assert "Nothing compares them" not in text
    # What still describes a line that is still there stays.
    assert "There are TWO roles on purpose" in text
    assert "# The APP role's password." in text
    assert "# POSTGRES_PASSWORD moved to postgres-init.env (docs/17 F52" in text
    # The Redis lines now carry the current template's comments.
    lines = text.splitlines()
    for key in ("REDIS_PASSWORD", "REDIS_URL"):
        at = next(i for i, line in enumerate(lines) if line.startswith(f"{key}="))
        wanted = _helper()._template_comment(prod, key)
        assert wanted and lines[at - len(wanted):at] == wanted, key
    # And a second run finds nothing left to replace.
    assert _run(prod)[1] == ["nothing to change: the files are already in this release's layout"]


def test_an_operators_own_comment_is_left_as_written(prod):
    text = OLD_SECRETS.replace(f"POSTGRES_PASSWORD={OWNER}",
                               f"# rotated by ops in March\nPOSTGRES_PASSWORD={OWNER}")
    (prod / "secrets.env").write_text(text, encoding="utf-8")
    (prod / "postgres-init.env").write_text(OLD_INIT, encoding="utf-8")
    _run(prod)
    assert "# rotated by ops in March" in (prod / "secrets.env").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Files it may not read or write (review of 2026-10-02)
# ---------------------------------------------------------------------------

_AS_OWNER = ("run this as the user who owns the secrets files, with sudo on Linux "
             "(sudo ./release/install.sh --production-secrets) or as that user on "
             "Windows.")


def test_an_unreadable_file_is_one_sentence_naming_it_and_sudo(prod, monkeypatch):
    """Root's mode 600 files read by anybody else: a PermissionError
    traceback until 2026-10-02, after which install.sh said "what is left
    is listed above" over nothing."""
    _old_layout(prod)
    before = {p.name: p.read_bytes() for p in prod.iterdir()}
    real = Path.read_bytes

    def read_bytes(self):
        if self.name == "secrets.env":
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    status, said = _run(prod)
    assert status == 1
    assert said == [f"refused: cannot read secrets.env in {prod} (Permission denied): "
                    f"{_AS_OWNER} Nothing was written."]
    monkeypatch.undo()
    assert {p.name: p.read_bytes() for p in prod.iterdir()} == before


def test_a_file_that_is_not_utf8_is_one_sentence_and_no_traceback(prod):
    """The docstring promises a file the helper cannot read is one sentence
    and never a traceback, and only OSError was caught: a Windows-1252
    comment ended in a UnicodeDecodeError (2026-10-03). The
    sentence says where the byte is, never what it is."""
    _old_layout(prod)
    with (prod / "secrets.env").open("ab") as handle:
        handle.write(b"# caf\xe9 comment\n")
    before = {p.name: p.read_bytes() for p in prod.iterdir()}
    at = before["secrets.env"].index(b"\xe9")
    status, said = _run(prod)
    assert status == 1
    assert said == [f"refused: secrets.env in {prod} is not UTF-8 text (invalid continuation "
                    f"byte, at byte {at}); save it as UTF-8 and run this again. "
                    f"Nothing was written."]
    assert {p.name: p.read_bytes() for p in prod.iterdir()} == before
    run = subprocess.run([sys.executable, str(HELPER), "--dir", str(prod)],
                         capture_output=True, text=True, timeout=60)
    assert run.returncode == 1 and run.stdout.startswith("refused: secrets.env in ")
    assert "Traceback" not in run.stdout + run.stderr


_LAST = ("secrets.env is written last, so it still holds every line it had; once that "
         "is fixed, run this again and it finishes what is left.")


@pytest.mark.parametrize("failing, changed", [
    ("postgres-init.env",
     "No secrets file was changed, so run this again once that is fixed."),
    ("migrate.env",
     f"Already changed, each with its backup beside it: postgres-init.env. {_LAST}"),
    ("secrets.env",
     f"Already changed, each with its backup beside it: postgres-init.env, migrate.env. "
     f"{_LAST}"),
])
def test_a_file_it_cannot_write_stops_it_naming_the_file_and_what_changed(
        prod, monkeypatch, failing, changed):
    """2026-10-03: the file the owner's lines leave is written
    LAST, whichever write fails, so secrets.env keeps them until the files
    they move into hold them, and running it again finishes the job."""
    _old_layout(prod)
    before = (prod / "secrets.env").read_bytes()
    helper = _helper()
    real = os.replace

    def replace(src, dst):
        if Path(dst).name == failing:
            raise PermissionError(13, "Permission denied", str(dst))
        return real(src, dst)

    monkeypatch.setattr(helper.os, "replace", replace)
    said = []
    status = helper.apply(prod, out=said.append, stamp=STAMP)
    assert status == 1
    assert said[-1] == (f"stopped: cannot write {failing} in {prod} (Permission denied): "
                        f"{_AS_OWNER} {changed}")
    assert not list(prod.glob(".*.tmp-*")), "a temporary file was left behind"
    for line in said:
        for value in VALUES:
            assert value not in line
    # The point of the order: the owner's lines are still where they were.
    assert (prod / "secrets.env").read_bytes() == before
    # And a re-run, with the cause gone, converges on the finished layout.
    monkeypatch.undo()
    status, said = _run(prod)
    assert status == 0, said
    assert config.OWNER_PASSWORD_ENV not in _env(prod / "secrets.env")
    assert config.MIGRATION_DSN_ENV not in _env(prod / "secrets.env")
    assert _env(prod / "postgres-init.env")[config.OWNER_PASSWORD_ENV] == OWNER
    assert _env(prod / "migrate.env")[config.MIGRATION_DSN_ENV] == \
        f"postgresql+psycopg://noctornal:{OWNER}@postgres:5432/noctornal"
    assert not any("make them the same" in line for line in said), said


def test_a_blocked_last_write_leaves_the_real_dsn_where_a_rerun_finds_it(prod):
    """The verifier's reproduction, with no stand-in: a DIRECTORY named
    migrate.env fails the second moved-to write for real. Written the old
    way (secrets.env first) the run ended with the owner password gone from
    secrets.env, a re-run made migrate.env from its template, and the real
    DSN lived in secrets.env.backup-STAMP alone, behind a "make them the
    same" message that was wrong."""
    _old_layout(prod)
    (prod / "migrate.env").mkdir()
    before = (prod / "secrets.env").read_bytes()
    said = []
    assert _helper().apply(prod, out=said.append, stamp=STAMP) == 1
    assert said[-1].startswith(f"stopped: cannot write migrate.env in {prod} (")
    assert said[-1].endswith(_LAST)
    assert (prod / "secrets.env").read_bytes() == before
    assert OWNER in (prod / "secrets.env").read_text(encoding="utf-8")
    (prod / "migrate.env").rmdir()
    status, said = _run(prod)
    assert status == 0, said
    assert _env(prod / "migrate.env")[config.MIGRATION_DSN_ENV] == \
        f"postgresql+psycopg://noctornal:{OWNER}@postgres:5432/noctornal"
    assert OWNER not in (prod / "secrets.env").read_text(encoding="utf-8")
    assert not any("make them the same" in line for line in said), said


def test_a_failed_chmod_leaves_the_file_it_was_for_as_it_was(prod, monkeypatch):
    """chmod comes BEFORE the rename (2026-10-03). After it, a
    chmod that failed on secrets.env left the file replaced while the run
    said it had not been written."""
    _old_layout(prod)
    before = (prod / "secrets.env").read_bytes()
    helper = _helper()
    real = os.chmod

    def chmod(path, mode, *args, **kwargs):
        name = Path(path).name
        if name == "secrets.env" or name.startswith(".secrets.env.tmp-"):
            raise PermissionError(1, "Operation not permitted", str(path))
        return real(path, mode, *args, **kwargs)

    monkeypatch.setattr(helper.os, "chmod", chmod)
    said = []
    assert helper.apply(prod, out=said.append, stamp=STAMP) == 1
    assert said[-1].startswith(f"stopped: cannot write secrets.env in {prod} (Operation not "
                               f"permitted): ")
    assert said[-1].endswith(_LAST)
    assert (prod / "secrets.env").read_bytes() == before
    assert not list(prod.glob(".*.tmp-*")), "a temporary file was left behind"


@pytest.mark.skipif(os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a user that is not root")
def test_install_sh_on_a_file_it_cannot_read_says_sudo_and_no_traceback(prod):
    """The verifier's reproduction, on the real permission bits: CI runs
    it as a user that is not root."""
    _old_layout(prod)
    (prod / "secrets.env").chmod(0)
    try:
        run = subprocess.run(["bash", str(ROOT / "release" / "install.sh"),
                              "--production-secrets", "--dir", str(prod)],
                             capture_output=True, text=True, timeout=120,
                             env=_path_with_this_python())
    finally:
        (prod / "secrets.env").chmod(0o600)
    out = run.stdout + run.stderr
    assert run.returncode == 1, out
    assert "cannot read secrets.env" in out and "sudo ./release/install.sh" in out
    assert "Traceback" not in out


class _RecordingOs:
    """The os module, with every mode `open` creates a file with and every
    `chmod` recorded, so the 0600 promise is held on Windows as well, where
    chmod only toggles read-only and the bits cannot be read back."""

    def __init__(self):
        self.created, self.chmodded = [], []

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, mode=0o777, *args, **kwargs):
        if flags & os.O_CREAT:
            self.created.append((Path(path).name, mode))
        return os.open(path, flags, mode, *args, **kwargs)

    def chmod(self, path, mode, *args, **kwargs):
        self.chmodded.append((Path(path).name, mode))
        return os.chmod(path, mode, *args, **kwargs)


def test_every_file_and_backup_is_created_and_left_mode_600(prod, monkeypatch):
    _old_layout(prod)
    helper = _helper()
    recording = _RecordingOs()
    monkeypatch.setattr(helper, "os", recording)
    assert helper.apply(prod, out=lambda line: None, stamp=STAMP) == 0
    assert recording.created and all(mode == 0o600 for _, mode in recording.created), \
        recording.created
    # A file is chmodded as the temporary it is written to, before the
    # rename (2026-10-03), so ".NAME.tmp-PID" stands for NAME.
    assert {re.sub(r"^\.(.+)\.tmp-\d+$", r"\1", name) for name, _ in recording.chmodded} == {
        "secrets.env", "postgres-init.env", "migrate.env",
        f"secrets.env.backup-{STAMP}", f"postgres-init.env.backup-{STAMP}"}
    assert all(mode == 0o600 for _, mode in recording.chmodded), recording.chmodded


# ---------------------------------------------------------------------------
# A fresh deployment
# ---------------------------------------------------------------------------

def test_a_fresh_directory_gets_its_redis_secret_and_is_asked_for_the_owners(prod):
    status, said = _run(prod)
    assert status == 1
    assert "created secrets.env from secrets.env.example (mode 600)" in said
    secrets = _env(prod / "secrets.env")
    assert "replace-me" not in secrets["REDIS_PASSWORD"]
    assert secrets["REDIS_URL"] == \
        f"redis://{LIMITER_ACL_USER}:{secrets['REDIS_PASSWORD']}@redis:6379/0"
    assert any(s.startswith("still to do: choose the schema owner's password") for s in said)
    assert "replace-me" in _env(prod / "postgres-init.env")[config.OWNER_PASSWORD_ENV]
    # The placeholders still to fill are named, never shown.
    assert any(s.startswith("note: secrets.env still carries a placeholder in ") and
               "NOCTORNAL_TOTP_KEK" in s for s in said)


def test_a_new_database_gets_an_owner_password_in_both_files(prod):
    status, said = _run(prod, new_database=True)
    assert status == 0, said
    owner = _env(prod / "postgres-init.env")[config.OWNER_PASSWORD_ENV]
    dsn = _env(prod / "migrate.env")[config.MIGRATION_DSN_ENV]
    assert "replace-me" not in owner and urlsplit(dsn).password == owner
    assert urlsplit(dsn).username == "noctornal" and urlsplit(dsn).hostname == "postgres"
    assert config.migration_job_problems({"NOCTORNAL_ENV": "production",
                                          config.MIGRATION_DSN_ENV: dsn}) == []
    assert not any(owner in s for s in said)


def test_an_existing_owner_password_is_never_regenerated(prod):
    _old_layout(prod)
    _run(prod, new_database=True)
    assert _env(prod / "postgres-init.env")[config.OWNER_PASSWORD_ENV] == OWNER


def test_generated_secrets_differ_from_run_to_run(tmp_path):
    seen = set()
    for n in range(2):
        directory = tmp_path / str(n)
        directory.mkdir()
        for name in ("secrets.env.example", "postgres-init.env.example", "migrate.env.example"):
            shutil.copy(PROD / name, directory / name)
        _helper().apply(directory, out=lambda line: None, new_database=True)
        seen.add(_env(directory / "secrets.env")["REDIS_PASSWORD"])
        seen.add(_env(directory / "postgres-init.env")[config.OWNER_PASSWORD_ENV])
    assert len(seen) == 4


def test_a_missing_template_is_refused(tmp_path):
    status, said = _run(tmp_path)
    assert status == 1 and said[0].startswith("refused: secrets.env is missing and so is")


# ---------------------------------------------------------------------------
# The helper's own constants, and its command line
# ---------------------------------------------------------------------------

def test_the_helpers_constants_are_the_applications():
    """It imports nothing from the application (it runs on a host python),
    so the names it shares are held equal here."""
    helper = _helper()
    assert helper.LIMITER_USER == LIMITER_ACL_USER
    for marker in helper.PUBLISHED:
        assert config._published_in(f"x{marker}x") is not None, marker
    compose = (PROD / "compose.yml").read_text(encoding="utf-8")
    assert f"POSTGRES_USER: {helper.OWNER_ROLE}\n" in compose


def test_the_command_line_exits_with_the_verdict(prod):
    _old_layout(prod)
    run = subprocess.run([sys.executable, str(HELPER), "--dir", str(prod)],
                         capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr
    for value in VALUES:
        assert value not in run.stdout + run.stderr
    missing = subprocess.run([sys.executable, str(HELPER), "--dir", str(prod / "nowhere")],
                             capture_output=True, text=True, timeout=60)
    assert missing.returncode == 1 and missing.stdout.startswith("refused:")


# ---------------------------------------------------------------------------
# The installers
# ---------------------------------------------------------------------------

def _path_with_this_python() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
    return env


def _bash() -> str | None:
    if os.name == "nt":
        candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
        return str(candidate) if candidate.is_file() else None
    return shutil.which("bash")


@pytest.mark.skipif(_bash() is None, reason="no bash on this machine")
def test_install_sh_production_secrets_runs_the_helper(prod):
    _old_layout(prod)
    run = subprocess.run([_bash(), str(ROOT / "release" / "install.sh"),
                          "--production-secrets", "--dir", str(prod)],
                         capture_output=True, text=True, timeout=120,
                         env=_path_with_this_python())
    out = run.stdout + run.stderr
    assert run.returncode == 0, out
    assert "moved POSTGRES_PASSWORD from secrets.env to postgres-init.env" in out
    assert "in this release's layout" in out
    assert config.OWNER_PASSWORD_ENV not in _env(prod / "secrets.env")
    for value in VALUES:
        assert value not in out


@pytest.mark.skipif(_bash() is None, reason="no bash on this machine")
def test_install_sh_reports_what_is_left_and_exits_1(prod):
    run = subprocess.run([_bash(), str(ROOT / "release" / "install.sh"),
                          "--production-secrets", "--dir", str(prod)],
                         capture_output=True, text=True, timeout=120,
                         env=_path_with_this_python())
    assert run.returncode == 1, run.stdout + run.stderr
    assert "still to do: choose the schema owner's password" in run.stdout
    # The whole sentence, not "not finished" (2026-10-03): the
    # old one, "what is left is listed above, and nothing it refused was
    # written", was false for a stop that listed nothing, and a substring
    # check let it back in unnoticed.
    assert _NOT_FINISHED in run.stdout


#: What both installers say when the helper exits non-zero.
_NOT_FINISHED = ("not finished: the lines above say what is left, or why it stopped and "
                 "what it changed")


def test_the_installers_say_a_stop_the_same_true_way_and_lock_the_same_files():
    """What is held about install.ps1 on every platform, run or not.

    It is the Windows installer (backslashed paths, icacls), so the run
    below exists on Windows alone. This is the half that exists everywhere,
    and it was written as a skip until 2026-10-03, which CI's Linux runner
    counted as a skipped test and the "No tests were skipped" gate failed
    the build for (2026-10-03)."""
    sh = (ROOT / "release" / "install.sh").read_text(encoding="utf-8")
    ps1 = (ROOT / "release" / "install.ps1").read_text(encoding="utf-8")
    for name, text in (("install.sh", sh), ("install.ps1", ps1)):
        assert _NOT_FINISHED in text, name
        assert "what is left is listed above" not in text, name
        assert "nothing it refused was written" not in text, name
    # The lock-down names exactly the files the helper writes, and backups.
    helper = _helper()
    names = re.search(r"\$_\.Name -in @\(([^)]*)\)", ps1)
    assert names, "install.ps1 no longer names the files it restricts to its user"
    assert set(re.findall(r"'([^']+)'", names.group(1))) == {
        helper.SECRETS, helper.POSTGRES_INIT, helper.MIGRATE}
    assert "*.env.backup-*" in ps1
    # Each hands the helper's own verdict back as its exit status.
    assert "production_secrets.py" in ps1 and "'--dir'" in ps1 and "exit $status" in ps1
    assert "production_secrets.py" in sh and "--dir" in sh and 'exit "$status"' in sh


if os.name == "nt":
    # Defined on Windows only, and not skipped anywhere else: a skip is a
    # line in CI's summary that fails its gate, and a test that quietly
    # passes without running proves nothing. install.ps1 is not run off
    # Windows (its helper path is backslashed, its lock-down is icacls), and
    # the test above holds what can be held there.
    def test_install_ps1_production_secrets_runs_the_helper_and_locks_the_files(prod):
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        assert powershell, "Windows without PowerShell: install.ps1 cannot run"
        _old_layout(prod)
        run = subprocess.run([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                              str(ROOT / "release" / "install.ps1"), "-ProductionSecrets",
                              "-ProductionDir", str(prod)],
                             capture_output=True, text=True, timeout=180,
                             env=_path_with_this_python())
        out = run.stdout + run.stderr
        assert run.returncode == 0, out
        assert "moved NOCTORNAL_MIGRATION_DATABASE_URL from secrets.env to migrate.env" in out
        assert config.MIGRATION_DSN_ENV in _env(prod / "migrate.env")
        for value in VALUES:
            assert value not in out
        # The Windows stand-in for mode 600: no inherited entry, one grant.
        acl = subprocess.run(["icacls", str(prod / "migrate.env")], capture_output=True,
                             text=True, timeout=30).stdout
        granted = [line for line in acl.splitlines()[:-1] if ":(" in line]
        assert len(granted) == 1 and "(I)" not in acl, acl
