"""What the scripts, launchers and runtime warnings state, held to the code
and configuration they describe.

## Why this file exists

The Alpha 6 pre-release check (2026-09-23) found sentences that had been
true once and were not any more, in text an operator reads at the moment
they act on it:

* the startup warning and the readiness action for an evicting Redis said
  `infra/docker-compose.yml` sets `allkeys-lru`, after that file moved to
  `noeviction`;
* the launchers said losing `.env.local` meant re-enrolling
  authenticators, when the key also seals persona and victim credentials
  and every sample's data key;
* `bootstrap.py create-user` suggested `python scripts/bootstrap.py
  demo-case`, which exits 127 on a stock Ubuntu, and its import hint never
  named the project's virtual environment;
* `refresh_counters.py` called `Path.read_text(newline=...)`, which
  Python 3.12, the documented minimum, does not have;
* `redact_dead_letters.py` printed a bracketed plural that docs/18
  quotes word for word;
* the production compose file described the dev file as it used to be.

Each check below holds one of those to its source, so the sentence fails
here when the thing it describes changes.

Pure: no database, no object store, no Redis. A script that does work at
import is read with `ast` or run in a subprocess rather than imported.
"""
from __future__ import annotations

import ast
import importlib.util
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from test_install_copy import _literals, _printed_lines, printed_docstring
from test_redis_policy_probe import FakeRedis
from test_server_copy_no_dashes import DASHES, FAKE_DASH
from test_server_copy_no_lazy_plurals import HEDGE

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
INSTALL_SH = ROOT / "release" / "install.sh"
INSTALL_PS1 = ROOT / "release" / "install.ps1"
LAUNCH_SH = SCRIPTS / "launch.sh"
LAUNCH_PS1 = SCRIPTS / "launch.ps1"
DEV_COMPOSE = ROOT / "infra" / "docker-compose.yml"
PROD_COMPOSE = ROOT / "infra" / "production" / "compose.yml"
README = ROOT / "README.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _load(name: str):
    """A script with no side effects at import, loaded by path."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bootstrap():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import bootstrap
    return bootstrap


# ---------------------------------------------------------------------------
# The dev Redis policy, as the startup warning and the register state it
# ---------------------------------------------------------------------------

def _dev_redis_policy() -> str:
    match = re.search(r"(?m)^\s*command:\s*redis-server\b.*--maxmemory-policy\s+(\S+)",
                      _read(DEV_COMPOSE))
    assert match, "the dev Redis command moved; this test is blind"
    return match.group(1)


#: A present-tense claim that the bundled compose file runs an evicting
#: policy. A past-tense record ("ran `allkeys-lru` until ...") is history
#: and is not matched.
_EVICTING_CLAIM = re.compile(
    r"docker-compose\.yml`?\s+(?:runs|sets)\b[^.;]*?\b(?:allkeys|volatile)-")


@pytest.fixture
def evicting_redis(monkeypatch):
    import redis
    monkeypatch.delenv("NOCTORNAL_RATELIMIT", raising=False)
    monkeypatch.setenv("REDIS_URL", "redis://limiter.test:6379/0")
    fake = FakeRedis("allkeys-lru")
    monkeypatch.setattr(redis.Redis, "from_url",
                        classmethod(lambda cls, url, **kw: fake))
    return fake


def test_the_startup_warning_names_the_policy_the_bundled_stack_runs(
        evicting_redis, caplog):
    from noctornal_api.http.limits import EVICTION_WARNING, build_limiter
    caplog.set_level(logging.INFO, logger="noctornal.ratelimit")
    build_limiter()
    text = " ".join(r.getMessage() for r in caplog.records
                    if r.levelno >= logging.WARNING)
    assert EVICTION_WARNING in text, "the warning itself is unchanged"
    policy = _dev_redis_policy()
    assert f"infra/docker-compose.yml runs {policy}" in text, text
    assert not _EVICTING_CLAIM.search(text), text
    assert "docker compose -f infra/docker-compose.yml up -d" in text


def test_the_readiness_action_names_the_policy_the_bundled_stack_runs(
        evicting_redis):
    from noctornal_api import readiness
    check = readiness._redis_limiter_store(None)
    assert check.ok is False, "an evicting Redis still fails the row"
    policy = _dev_redis_policy()
    assert f"infra/docker-compose.yml runs {policy}" in check.action, check.action
    assert not _EVICTING_CLAIM.search(check.action), check.action
    assert "docker compose -f infra/docker-compose.yml up -d" in check.action


def test_no_docstring_says_the_bundled_redis_evicts():
    from noctornal_api import ratelimit
    from noctornal_api.http import limits
    probe = ast.get_docstring(ast.parse(
        _read(ROOT / "apps" / "api" / "tests" / "test_redis_policy_probe.py")))
    for name, doc in (("ratelimit", ratelimit.__doc__),
                      ("limits._warn_if_evicting", limits._warn_if_evicting.__doc__),
                      ("test_redis_policy_probe", probe)):
        assert not _EVICTING_CLAIM.search(_flat(doc)), name
    # And the one that states the policy states the file's.
    assert f"`infra/docker-compose.yml` runs `{_dev_redis_policy()}`" in _flat(
        ratelimit.__doc__)


# ---------------------------------------------------------------------------
# The production compose file's account of the dev file
# ---------------------------------------------------------------------------

def _comments(text: str) -> str:
    return _flat(" ".join(line.split("#", 1)[1] for line in text.split("\n")
                          if line.lstrip().startswith("#")))


def _image(text: str, repo: str) -> str:
    tags = set(re.findall(rf"(?m)^\s*image:\s*({re.escape(repo)}:\S+)", text))
    assert len(tags) == 1, (repo, tags)
    return tags.pop()


def test_the_production_file_describes_the_dev_file_as_it_is():
    prod, dev = _read(PROD_COMPOSE), _read(DEV_COMPOSE)
    notes = _comments(prod)
    assert not re.search(r"(?i)\bdev runs `?allkeys", notes)
    assert "is the whole difference from dev" not in notes
    assert "`:latest` matches the dev file" not in notes
    # "Dev publishes six ports, on 127.0.0.1 only".
    published = []
    for entries in re.findall(r"(?m)^\s*ports:\s*\[(.*)\]", dev):
        published += re.findall(r'"([^"]+)"', entries)
    assert len(published) == 6 and all(p.startswith("127.0.0.1:") for p in published)
    assert "Dev publishes six ports, on 127.0.0.1 only" in notes
    # "pinned to the same RELEASE tag as the dev file".
    assert "same RELEASE tag as the dev file" in notes
    minio = "quay.io/minio/minio"
    assert _image(prod, minio) == _image(dev, minio)
    assert ":latest" not in _image(prod, minio)
    # And both Redis services run the policy the notes say they share.
    assert _dev_redis_policy() == "noeviction"
    assert "--maxmemory-policy noeviction" in prod


# ---------------------------------------------------------------------------
# What losing .env.local costs
# ---------------------------------------------------------------------------

#: SEALED_COLUMNS table -> the word a key-loss warning uses for it. None is
#: a column nothing writes, so a warning naming it would describe nothing.
_SEALED_WORDS = {
    "iam.app_user": "authenticator",
    "collect.collection_account": "persona",
    "ingest.victim_credential": "victim",
    "lab.sample": "sample",
    "collect.egress_profile": None,
    "notify.jira_destination": "jira",  # F7
    "ingest.provider": "lookup provider",  # F15.2
}


def test_every_sealed_column_has_a_word_in_the_key_loss_warnings():
    """A column added to SEALED_COLUMNS fails here until the warnings below
    say what losing the key costs it."""
    from noctornal_api.security.sealed import SEALED_COLUMNS
    assert {table for table, _, _ in SEALED_COLUMNS} == set(_SEALED_WORDS)


def test_the_unnamed_sealed_column_is_still_one_nothing_writes():
    """collect.egress_profile is left out of the warnings because nothing
    writes its ciphertext. The day something does, it belongs in them."""
    writers = []
    for base in (ROOT / "apps" / "api" / "src", SCRIPTS):
        for path in base.rglob("*.py"):
            if path.name != "sealed.py" and "endpoint_ciphertext" in path.read_text(
                    encoding="utf-8"):
                writers.append(str(path.relative_to(ROOT)))
    assert not writers, writers


def _between(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


#: (file, where the generated header starts). It ends at the key's line.
_HEADERS = (
    (INSTALL_SH, "# Generated by install.sh"),
    (INSTALL_PS1, "# Generated by install.ps1"),
    (LAUNCH_SH, "# NocTORnal local key store"),
    (LAUNCH_PS1, "# NocTORnal local key store"),
)


@pytest.mark.parametrize("path,start", _HEADERS, ids=lambda v: getattr(v, "name", ""))
def test_the_generated_file_says_everything_its_key_seals(path: Path, start: str):
    header = _between(_read(path), start, "NOCTORNAL_TOTP_KEK=")
    text = _flat(header.replace("''", "'")).lower()
    for table, word in _SEALED_WORDS.items():
        if word:
            assert word in text, (path.name, table, word)
    assert "re-enrol" in text and "decrypted" in text, path.name
    # The pepper: the installers write it; the launchers only mention it,
    # because a file they create holds the key alone.
    assert "noctornal_ingest_pepper" in text and "ingest key" in text, path.name
    assert "fingerprint" in text, path.name


@pytest.mark.parametrize("path", (LAUNCH_SH, LAUNCH_PS1), ids=lambda p: p.name)
def test_the_launchers_box_says_more_than_authenticators(path: Path):
    box = _flat(_between(_read(path), "A NEW TOTP KEY WAS GENERATED",
                         "Keep a backup")).lower()
    for word in ("authenticator", "persona", "victim", "sample", "decrypted"):
        assert word in box, (path.name, word)


@pytest.mark.parametrize("path", (INSTALL_SH, INSTALL_PS1), ids=lambda p: p.name)
def test_the_installers_backup_note_says_more_than_a_lockout(path: Path):
    text = _flat(" ".join(line for _, line in _printed_lines(path)))
    assert "locks every account out" not in text
    assert "no stored credential or sample can be decrypted" in text, path.name


# ---------------------------------------------------------------------------
# bootstrap.py create-user: what to do next, and the import hint
# ---------------------------------------------------------------------------

def _next_block(capsys, roles: list[str], *, windows: bool) -> str:
    _bootstrap()._print_next("you@example.org", roles, windows=windows)
    return capsys.readouterr().out


@pytest.mark.parametrize("windows,prefix", [
    (False, [".venv/bin/python", "scripts/bootstrap.py"]),
    (True, [".venv\\Scripts\\python", "scripts\\bootstrap.py"]),
], ids=["posix", "windows"])
def test_create_user_points_at_the_console_and_the_readme_recipe(
        capsys, windows, prefix):
    bootstrap = _bootstrap()
    out = _next_block(capsys, ["CASE_OWNER", "SYS_ADMIN"], windows=windows)
    assert bootstrap.CONSOLE_URL == "http://127.0.0.1:8000/ui/"
    assert bootstrap.CONSOLE_URL in out
    assert 'README.md, section "First run"' in _flat(out)
    assert "demo-case" not in out and "POST /api/v1/auth/login" not in out
    command = next(line for line in out.splitlines() if "demo-network" in line).split()
    assert command[:2] == prefix, command
    args = bootstrap._build_parser().parse_args(command[2:])
    assert args.func is bootstrap.cmd_demo_network
    assert (args.owner_email, args.code, args.classification) == (
        "you@example.org", "OP-SHOWCASE-26", "CLEAR")


def test_the_suggested_command_is_the_readme_recipes_first_line():
    readme = _read(README)
    first_run = readme[readme.index("## First run"):]
    recipe = _flat(first_run.replace("\\\n", " "))
    assert ("scripts/bootstrap.py demo-network --owner-email you@example.org "
            "--code OP-SHOWCASE-26 --classification CLEAR") in recipe
    # The console URL's port is the installers' and launchers' default.
    for path in (INSTALL_SH, LAUNCH_SH):
        assert re.search(r"(?m)^PORT=8000$", _read(path)), path.name
    for path in (INSTALL_PS1, LAUNCH_PS1):
        assert re.search(r"\[int\]\s+\$Port = 8000", _read(path)), path.name


def test_create_user_offers_the_showcase_only_to_a_case_owner(capsys):
    """The recipe makes the account the showcase case's owner, which is not
    what a second person given SECURITY_OFFICER is for."""
    out = _next_block(capsys, ["SECURITY_OFFICER"], windows=False)
    assert "demo-network" not in out
    assert _bootstrap().CONSOLE_URL in out


def test_the_import_hint_names_the_projects_virtual_environment():
    """Run without site-packages, so nothing the script imports is found:
    the hint is what a system interpreter prints."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-S", str(SCRIPTS / "bootstrap.py"), "list-users"],
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
        timeout=120)
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    bootstrap = _bootstrap()
    python, script = bootstrap._venv_python(), bootstrap._this_script()
    assert "cannot import the API package" in proc.stderr
    assert f"{python} {script} <command>" in proc.stderr, proc.stderr
    # With the pins: without them pip takes the newest release of every >=
    # floor (c3, 2026-09-24).
    assert (f"{python} -m pip install -c constraints.txt -e "
            in proc.stderr), proc.stderr
    assert "db/requirements.txt" not in proc.stderr
    assert not any(line.strip().startswith("pip install")
                   for line in proc.stderr.splitlines()), proc.stderr


# ---------------------------------------------------------------------------
# refresh_counters.py on Python 3.12
# ---------------------------------------------------------------------------

def _read_text_calls_with_newline(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "read_text"
            and any(kw.arg == "newline" for kw in node.keywords)]


def test_nothing_passes_newline_to_read_text():
    """`Path.read_text` takes `newline` from Python 3.13 only, and the
    floor is 3.12 (pyproject's requires-python)."""
    assert '>=3.12' in _read(ROOT / "apps" / "api" / "pyproject.toml")
    found = []
    for base in (SCRIPTS, ROOT / "apps" / "api" / "src", ROOT / "apps" / "api" / "tests",
                 ROOT / "packages", ROOT / "db"):
        for path in base.rglob("*.py"):
            if ".venv" in path.parts:
                continue
            found += [f"{path.relative_to(ROOT)}:{n}"
                      for n in _read_text_calls_with_newline(path)]
    assert not found, found


def test_refresh_counters_runs_on_3_12_and_keeps_each_files_line_endings(
        tmp_path, monkeypatch, capsys):
    refresher = _load("refresh_counters")
    original = Path.read_text

    def read_text_3_12(self, encoding=None, errors=None):
        # Python 3.12's signature: no `newline`.
        return original(self, encoding=encoding, errors=errors)

    monkeypatch.setattr(Path, "read_text", read_text_3_12)
    (tmp_path / "CRLF.md").write_bytes(b"It has 1234 tests.\r\n" * 5)
    (tmp_path / "LF.md").write_bytes(b"It has 1234 tests.\n" * 5)
    monkeypatch.setattr(refresher, "ROOT", tmp_path)
    monkeypatch.setattr(refresher, "CHECKED", {"CRLF.md": None, "LF.md": None})
    monkeypatch.setattr(refresher, "_values", lambda: {
        "tests": "2600", "revisions": "65", "head": "0065",
        "version": "0.6.0", "completion": "92.8"})
    assert refresher.refresh(check=False) == 0
    assert (tmp_path / "CRLF.md").read_bytes() == b"It has 2600 tests.\r\n" * 5
    assert (tmp_path / "LF.md").read_bytes() == b"It has 2600 tests.\n" * 5
    capsys.readouterr()


# ---------------------------------------------------------------------------
# Plurals and dashes in what the scripts print
# ---------------------------------------------------------------------------

def _function(path: Path, name: str):
    """One pure function from a script, compiled on its own, because
    importing the script loads .env.local and connects to nothing useful."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    node = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == name)
    namespace: dict = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"),
         namespace)
    return namespace[name]


def test_redact_dead_letters_agrees_in_number_and_docs_18_quotes_it():
    rows = _function(SCRIPTS / "redact_dead_letters.py", "_rows")
    assert rows(1) == "1 row" and rows(0) == "0 rows" and rows(3) == "3 rows"
    assert rows(1, "unredacted dead-letter") == "1 unredacted dead-letter row"
    zero = rows(0, "unredacted dead-letter")
    assert zero == "0 unredacted dead-letter rows"
    docs = _flat(_read(ROOT / "docs" / "18-legal-review-pack.md"))
    assert f'`scripts/redact_dead_letters.py` reports "{zero}"' in docs


def test_no_script_prints_a_bracketed_plural():
    offenders = []
    for path in sorted(SCRIPTS.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for node, _, _ in _literals(ast.parse(source)):
            if HEDGE.search(node.value):
                offenders.append((path.name, node.lineno, node.value[:80]))
        for n, line in enumerate(printed_docstring(source).split("\n"), 1):
            if HEDGE.search(line):
                offenders.append((path.name, f"docstring line {n}", line.strip()))
    assert not offenders, offenders


@pytest.mark.parametrize("path", (SCRIPTS / "open-ui.ps1",
                                  SCRIPTS / "package_release.ps1"),
                         ids=lambda p: p.name)
def test_the_other_powershell_scripts_print_no_dash(path: Path):
    offenders = [(n, line.strip()) for n, line in _printed_lines(path)
                 if any(d in line for d in DASHES) or FAKE_DASH.search(line)]
    assert not offenders, offenders


def test_open_ui_uses_the_launchers_dev_address():
    lines = [line for _, line in _printed_lines(SCRIPTS / "open-ui.ps1")]
    assert any("@127.0.0.1:5432/noctornal" in line for line in lines)
    assert not any("localhost" in line for line in lines)
