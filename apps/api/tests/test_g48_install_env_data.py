"""`.env.local` is data, never a script, and is private from its first byte
(infra-9, 2026-10-03).

release/install.sh ran `set -a; . "$ENV_LOCAL"; set +a`, which EXECUTES the
file: one that was handed over, restored from a backup or edited by hand ran as
the installing user, and a legitimate value with a `$`, an `&`, a `;` or a
space was mangled or run. scripts/launch.sh, scripts/_env.py and launch.ps1
parse the same file line by line for exactly that reason. It also wrote the
key store with the default umask and restricted it afterwards, and the
PowerShell scripts never restricted it at all.

The shell function is extracted from install.sh and run with bash; the
PowerShell scripts are read as text (they are parsed, not run, here: the
Windows proof is in the report).
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
INSTALL_SH = ROOT / "release" / "install.sh"
LAUNCH_SH = ROOT / "scripts" / "launch.sh"
INSTALL_PS1 = ROOT / "release" / "install.ps1"
LAUNCH_PS1 = ROOT / "scripts" / "launch.ps1"
OPEN_UI_PS1 = ROOT / "scripts" / "open-ui.ps1"
ENV_PY = ROOT / "scripts" / "_env.py"


def _bash() -> str | None:
    """A real bash: not WSL's launcher, which cannot see this test's files."""
    found = shutil.which("bash")
    if os.name != "nt":
        return found
    if found and not any(part in found.lower() for part in ("system32", "windowsapps")):
        return found
    git = shutil.which("git")
    if git:
        here = Path(git).resolve()
        for root in (here.parent.parent, here.parent.parent.parent):
            for rel in ("bin/bash.exe", "usr/bin/bash.exe"):
                if (root / rel).is_file():
                    return str(root / rel)
    return None


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


HOSTILE = (
    b"\xef\xbb\xbf# a BOM on the first line, then a comment\r\n"
    b"NOCTORNAL_TOTP_KEK=abc123\r\n"
    b"DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal\n"
    b"SMTP_FROM=ops@example.org$(echo CODE-RAN > PWNED-SUBST)\n"
    b"BACKTICK=`echo CODE-RAN > PWNED-TICK`\n"
    b"SEMICOLON=first;echo CODE-RAN > PWNED-SEMI\n"
    b"AMPERSAND=a & echo CODE-RAN > PWNED-AMP\n"
    b"SPACED=has some spaces in it\n"
    b'DOUBLE="double quoted"\n'
    b"SINGLE='single quoted'\n"
    b"export EXPORTED=yes\n"
    b"  INDENTED=ok\n"
    b"BAD-NAME=skipped\n"
    b"1BAD=skipped\n"
    b"NO_EQUALS_HERE\n"
    b"OVERRIDDEN=from-the-file\n"
)


def _function() -> str:
    match = re.search(r"(?ms)^load_env_local_as_data\(\) \{\n.*?^\}\n", _text(INSTALL_SH))
    assert match, "install.sh no longer defines load_env_local_as_data"
    return match.group(0)


def _run_loader(tmp_path: Path, content: bytes):
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    (tmp_path / ".env.local").write_bytes(content)
    script = tmp_path / "run.sh"
    script.write_text(
        "set -euo pipefail\n" + _function() +
        'cd "$1"\nOVERRIDDEN=from-the-environment; export OVERRIDDEN\n'
        'load_env_local_as_data ".env.local"\n'
        'for v in NOCTORNAL_TOTP_KEK DATABASE_URL SMTP_FROM BACKTICK SEMICOLON AMPERSAND SPACED '
        'DOUBLE SINGLE EXPORTED INDENTED OVERRIDDEN; do\n'
        '  printf "%s=<%s>\\n" "$v" "${!v-UNSET}"\n'
        'done\n', encoding="utf-8", newline="\n")
    done = subprocess.run([bash, script.as_posix(), tmp_path.as_posix()], capture_output=True,
                          text=True, encoding="utf-8", timeout=60)
    values = dict(re.findall(r"(?m)^(\w+)=<(.*)>$", done.stdout))
    return done, values


def test_the_installer_reads_the_file_as_data_and_runs_nothing_from_it(tmp_path):
    done, values = _run_loader(tmp_path, HOSTILE)
    assert done.returncode == 0, done.stderr
    assert not list(tmp_path.glob("PWNED*")), "a line of .env.local was executed"
    assert values["SMTP_FROM"] == "ops@example.org$(echo CODE-RAN > PWNED-SUBST)"
    assert values["BACKTICK"] == "`echo CODE-RAN > PWNED-TICK`"
    assert values["SEMICOLON"] == "first;echo CODE-RAN > PWNED-SEMI"
    assert values["AMPERSAND"] == "a & echo CODE-RAN > PWNED-AMP"


def test_the_installer_still_reads_every_ordinary_value_the_way_it_did(tmp_path):
    """Never narrow what a legitimate file can say: quotes, spaces, an export
    prefix, a BOM and Windows line endings, which the old sourcing handled
    or the PowerShell installer wrote."""
    done, values = _run_loader(tmp_path, HOSTILE)
    assert done.returncode == 0, done.stderr
    assert values["NOCTORNAL_TOTP_KEK"] == "abc123"
    assert values["DATABASE_URL"].endswith("@127.0.0.1:5432/noctornal")
    assert values["SPACED"] == "has some spaces in it"
    assert values["DOUBLE"] == "double quoted" and values["SINGLE"] == "single quoted"
    assert values["EXPORTED"] == "yes" and values["INDENTED"] == "ok"


def test_the_files_value_wins_over_the_environment_as_sourcing_made_it(tmp_path):
    """An exported DATABASE_URL pointing somewhere else must not receive the
    installer's migrations and seeds: the installer sets up what the file
    names."""
    _done, values = _run_loader(tmp_path, HOSTILE)
    assert values["OVERRIDDEN"] == "from-the-file"


def test_a_name_that_is_not_an_identifier_is_left_out_not_exported(tmp_path):
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    (tmp_path / ".env.local").write_bytes(b"BAD-NAME=skipped\n1BAD=skipped\nGOOD=kept\n")
    script = tmp_path / "run.sh"
    script.write_text("set -euo pipefail\n" + _function() +
                      'load_env_local_as_data "$1"\nenv | grep -c "BAD" || true\necho "$GOOD"\n',
                      encoding="utf-8", newline="\n")
    done = subprocess.run([bash, script.as_posix(), (tmp_path / ".env.local").as_posix()],
                          capture_output=True, text=True, timeout=60)
    assert done.stdout.split() == ["0", "kept"], done.stdout


def test_install_sh_no_longer_sources_the_file():
    code = [ln for ln in _text(INSTALL_SH).splitlines() if not ln.lstrip().startswith("#")]
    assert not any(re.search(r'(^|[;&|]\s*)(\.|source)\s+"?\$\{?ENV_LOCAL', ln) for ln in code), code
    assert not any("set -a" in ln for ln in code)
    assert any(ln.strip() == 'load_env_local_as_data "$ENV_LOCAL"' for ln in code)


def test_the_alembic_message_and_the_install_notes_do_not_say_to_source_the_file():
    refusal = _text(ROOT / "db" / "migrations" / "env.py")
    assert "set -a" not in "\n".join(ln for ln in refusal.splitlines() if not ln.lstrip().startswith("#"))
    assert "scripts/_env.py export" in refusal
    # The README's "Verifying the install" said `set -a; . ./.env.local; set +a`
    # while INSTALL.md read the file as data (Beta 1 clean machine, 2026-10-07).
    for doc in (ROOT / "README.md", ROOT / "release" / "INSTALL.md"):
        text = _text(doc)
        assert not re.search(r"(^|[;&|]\s*)(\.|source)\s+\S*\.env\.local", text, re.M), doc.name
        assert "set -a" not in text, doc.name
        assert 'eval "$(.venv/bin/python scripts/_env.py export)"' in text, doc.name


# --- private from the first byte ----------------------------------------------

@pytest.mark.parametrize("path", [INSTALL_SH, LAUNCH_SH], ids=lambda p: p.name)
def test_the_shell_scripts_create_the_key_store_under_umask_077(path):
    write = 'cat > "$ENV_LOCAL" <<EOF'
    text = _text(path)
    assert text.count(write) == 1
    before, after = text.split(write)
    assert before.rstrip().endswith("umask 077"), "umask 077 is the last thing before the write"
    assert re.search(r'umask "\$(PREVIOUS_UMASK|previous_umask)"\n\s*chmod 600 "\$ENV_LOCAL"',
                     after), "umask restored, and the chmod stays as the belt"


@pytest.mark.parametrize("path,write_marker", [
    (INSTALL_PS1, "'# Generated by install.ps1. Machine-local; never commit this file.'"),
    (LAUNCH_PS1, "'# NocTORnal local key store. Created by scripts/launch.ps1.'"),
])
def test_the_powershell_scripts_restrict_the_file_before_the_keys_are_written(path, write_marker):
    text = _text(path)
    assert "function Protect-EnvLocal" in text
    function = text[text.index("function Protect-EnvLocal"):]
    function = function[:function.index("\n}\n")]
    assert "icacls.exe" in function and "/inheritance:r" in function and "/grant:r" in function
    assert "WindowsIdentity]::GetCurrent().User.Value" in function
    create = text.index("New-Item -ItemType File -Path $EnvLocal -Force")
    protect = text.index("Protect-EnvLocal -Path $EnvLocal", create)
    assert create < protect < text.index(write_marker, protect)


# --- scripts/_env.py export ------------------------------------------------------

def _env_module(tmp_path: Path):
    spec = importlib.util.spec_from_file_location("g48_env", ENV_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.env_local_path = lambda: tmp_path / ".env.local"
    return module


def test_export_quotes_every_value_as_one_word(tmp_path, monkeypatch):
    (tmp_path / ".env.local").write_bytes(HOSTILE)
    for name in ("SMTP_FROM", "BACKTICK", "SEMICOLON", "AMPERSAND", "SPACED", "OVERRIDDEN"):
        monkeypatch.delenv(name, raising=False)
    statements = _env_module(tmp_path).export_statements()
    assert "export SMTP_FROM='ops@example.org$(echo CODE-RAN > PWNED-SUBST)'" in statements
    assert "export SPACED='has some spaces in it'" in statements
    assert not any(s.startswith(("export BAD-NAME", "export 1BAD")) for s in statements)


def test_export_leaves_alone_what_the_environment_already_sets(tmp_path, monkeypatch):
    (tmp_path / ".env.local").write_bytes(b"A_SET=file\nA_BLANK=file\nA_NEW=file\n")
    monkeypatch.setenv("A_SET", "from-the-shell")
    monkeypatch.setenv("A_BLANK", "")
    monkeypatch.delenv("A_NEW", raising=False)
    assert _env_module(tmp_path).export_statements() == ["export A_NEW=file"]


def test_eval_of_the_export_runs_nothing_from_the_file(tmp_path):
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(ENV_PY, scripts / "_env.py")
    (tmp_path / ".env.local").write_bytes(HOSTILE)
    script = tmp_path / "run.sh"
    script.write_text('cd "$1"\neval "$("$2" scripts/_env.py export)"\n'
                      'printf "%s" "$SMTP_FROM"\n', encoding="utf-8", newline="\n")
    env = {k: v for k, v in os.environ.items() if k not in ("SMTP_FROM", "OVERRIDDEN")}
    done = subprocess.run([bash, script.as_posix(), tmp_path.as_posix(), Path(sys.executable).as_posix()],
                          capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 0, done.stderr
    assert done.stdout == "ops@example.org$(echo CODE-RAN > PWNED-SUBST)"
    assert not list(tmp_path.glob("PWNED*"))


def test_load_env_local_still_does_what_it_did(tmp_path, monkeypatch):
    """The refactor behind `export` shares one line parser with the loader
    every script uses; its behaviour is unchanged."""
    (tmp_path / ".env.local").write_bytes(b"\xef\xbb\xbfFIRST=1\n# c\nSECOND = \"two\" \nEMPTY=\nTAKEN=file\n")
    for name in ("FIRST", "SECOND", "EMPTY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TAKEN", "shell")
    _env_module(tmp_path).load_env_local()
    assert (os.environ["FIRST"], os.environ["SECOND"], os.environ["EMPTY"], os.environ["TAKEN"]) == (
        "1", "two", "", "shell")


# --- names that change how programs start (g48 verification, 2026-10-03) ------
#
# Reading `.env.local` as data stops it running as shell syntax, but the
# loaders still exported any identifier in it, and install.sh lets the file's
# value win over the environment: `PYTHONPATH=./evil` with a sitecustomize.py,
# `PATH=./evilbin`, `LD_PRELOAD=./evil.so` or `BASH_ENV=./evil.sh` in a
# handed-over file ran code as the installing user in the next python or shell
# it started. All four loaders now leave those names out, say so by name, and
# agree on the list.

DANGEROUS = (
    b"PATH=./evilbin\nPYTHONPATH=./evilpp-CANARY\nPythonStartup=./evil.py\nLD_PRELOAD=./evil.so\n"
    b"LD_LIBRARY_PATH=./evil\nDYLD_INSERT_LIBRARIES=./evil.dylib\nBASH_ENV=./evil.sh\nENV=./evil.sh\n"
    b"IFS=x\nPS4=$(touch PWNED-PS4)\nPROMPT_COMMAND=touch PWNED-PC\nSHELLOPTS=xtrace\nCOMSPEC=evil.exe\n"
    b"Path=./evilbin\nHOME=./evilhome\n"
    # The tools the scripts start next (Beta 1 verification, 2026-10-07):
    # DOCKER_CONFIG held a fake cli-plugins/docker-compose that `docker compose`
    # ran as root. Mixed case on purpose: Windows names are case-insensitive.
    b"DOCKER_CONFIG=./evil\nDOCKER_HOST=tcp://203.0.113.9:2375\nCOMPOSE_FILE=./evil.yml\n"
    b"Git_Ssh_Command=./evil.sh\nPIP_INDEX_URL=http://evil.example/simple\n"
    b"NODE_OPTIONS=--require ./evil.js\nPSModulePath=./evil\n"
)
_DANGEROUS_NAMES = ("PATH", "PYTHONPATH", "PythonStartup", "LD_PRELOAD", "LD_LIBRARY_PATH",
                    "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV", "IFS", "PS4", "PROMPT_COMMAND",
                    "SHELLOPTS", "COMSPEC", "Path", "HOME",
                    "DOCKER_CONFIG", "DOCKER_HOST", "COMPOSE_FILE", "Git_Ssh_Command",
                    "PIP_INDEX_URL", "NODE_OPTIONS", "PSModulePath")
#: Prints every dangerous name's value, or UNSET. Some are always set by the
#: shell itself (IFS, PS4, SHELLOPTS, HOME), so the test compares a snapshot
#: before and after the loader rather than expecting them unset.
_SNAPSHOT_FUNCTION = ("snapshot() { local v; for v in " + " ".join(_DANGEROUS_NAMES) + "; do "
                      'printf "%s=<%s>\\n" "$v" "${!v-UNSET}"; done; }\n')
_ORDINARY = b"NOCTORNAL_TOTP_KEK=abc123\nDATABASE_URL=postgresql+psycopg://u:p@127.0.0.1:5432/d\nPATHOLOGY=ok\nHOMEPAGE=ok\nENVIRONMENT=ok\nG48_ORDINARY=fine\n"


def test_the_installer_leaves_out_a_name_that_changes_how_programs_start(tmp_path):
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    (tmp_path / ".env.local").write_bytes(DANGEROUS + _ORDINARY)
    script = tmp_path / "run.sh"
    script.write_text(
        "set -euo pipefail\n" + _function() + _SNAPSHOT_FUNCTION +
        'cd "$1"\nbefore="$(snapshot)"\n'
        'load_env_local_as_data ".env.local"\n'
        'after="$(snapshot)"\n'
        'echo "names-unchanged=$([ "$before" = "$after" ] && echo yes || echo NO)"\n'
        'echo "ordinary=$G48_ORDINARY $PATHOLOGY $HOMEPAGE $ENVIRONMENT"\n',
        encoding="utf-8", newline="\n")
    done = subprocess.run([bash, script.as_posix(), tmp_path.as_posix()], capture_output=True,
                          text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stderr
    assert "names-unchanged=yes" in done.stdout, done.stdout
    assert "ordinary=fine ok ok ok" in done.stdout, "a name that merely starts alike is a setting"
    for name in _DANGEROUS_NAMES:
        assert f".env.local: ignored {name}," in done.stderr, name
    assert "evil" not in done.stderr and "CANARY" not in done.stderr, "a value was printed"
    assert not list(tmp_path.glob("PWNED*"))


def test_the_python_loaders_leave_the_same_names_out_and_say_so(tmp_path, monkeypatch, capsys):
    (tmp_path / ".env.local").write_bytes(DANGEROUS + _ORDINARY)
    module = _env_module(tmp_path)
    environment: dict[str, str] = {}
    monkeypatch.setattr(os, "environ", environment)
    module.load_env_local()
    assert environment == {"NOCTORNAL_TOTP_KEK": "abc123",
                           "DATABASE_URL": "postgresql+psycopg://u:p@127.0.0.1:5432/d",
                           "PATHOLOGY": "ok", "HOMEPAGE": "ok", "ENVIRONMENT": "ok",
                           "G48_ORDINARY": "fine"}
    err = capsys.readouterr().err
    for name in _DANGEROUS_NAMES:
        assert f".env.local: ignored {name}," in err, name
    assert "evil" not in err and "CANARY" not in err, "a value was printed"
    environment.clear()           # `export` skips what is already set, so ask again from empty
    statements = module.export_statements()
    assert not any(re.match(r"export (%s)=" % "|".join(_DANGEROUS_NAMES), s) for s in statements)
    assert "export PATHOLOGY=ok" in statements


def _launch_sh_loop() -> str:
    match = re.search(r'(?ms)^if \[ -f "\$ENV_LOCAL" \]; then\n  detail "reading \$ENV_LOCAL"\n.*?^  done < "\$ENV_LOCAL"\nfi\n',
                      _text(LAUNCH_SH))
    assert match, "launch.sh no longer has its .env.local loop where this test looks"
    return match.group(0)


def test_launch_sh_leaves_the_same_names_out(tmp_path):
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    (tmp_path / ".env.local").write_bytes(DANGEROUS + _ORDINARY)
    script = tmp_path / "run.sh"
    script.write_text(
        "set -euo pipefail\ndetail() { printf '    %s\\n' \"$1\"; }\n" + _SNAPSHOT_FUNCTION +
        'cd "$1"\nENV_LOCAL=.env.local\nbefore="$(snapshot)"\n' + _launch_sh_loop() +
        'after="$(snapshot)"\n'
        'echo "names-unchanged=$([ "$before" = "$after" ] && echo yes || echo NO)"\n'
        'echo "ordinary=$G48_ORDINARY $PATHOLOGY $HOMEPAGE $ENVIRONMENT"\n',
        encoding="utf-8", newline="\n")
    done = subprocess.run([bash, script.as_posix(), tmp_path.as_posix()], capture_output=True,
                          text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "names-unchanged=yes" in done.stdout, done.stdout
    assert "ordinary=fine ok ok ok" in done.stdout
    for name in ("PATH", "PYTHONPATH", "LD_PRELOAD", "BASH_ENV", "Path", "HOME",
                 "DOCKER_CONFIG", "NODE_OPTIONS", "PSModulePath"):
        assert f"{name} ignored: it changes how programs start" in done.stdout, name
    assert "evil" not in done.stdout.replace("ignored", ""), "a value was printed"


def test_launch_sh_does_not_evaluate_a_subscript_in_a_name(tmp_path):
    """`${!name+x}` evaluates an array subscript, so a name like `x[$(cmd)]` ran
    `cmd` as the launching user: the sibling of infra-9 that install.sh closed
    with an identifier check and launch.sh did not (Beta 1 verification,
    2026-10-07; `release/start.sh` execs `launch.sh`). The real loop runs on the
    hostile lines. `>file` is a command with no spaces, because the loop strips
    them from a name."""
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    (tmp_path / ".env.local").write_bytes(
        b"x[$(>PWNED-SUBSCRIPT)]=1\n"
        b"y[`>PWNED-TICK`]=1\n"
        b"z[0]=1\n"
        b"w$(>PWNED-BARE)=1\n"
        b"BAD-NAME=skipped\n"
        b"1BAD=skipped\n"
        b"G57_ORDINARY=fine\n")
    script = tmp_path / "run.sh"
    script.write_text(
        "set -euo pipefail\ndetail() { printf '    %s\\n' \"$1\"; }\n"
        'cd "$1"\nENV_LOCAL=.env.local\n' + _launch_sh_loop() +
        'echo "ordinary=$G57_ORDINARY"\n'
        'echo "badnames=$(env | grep -c "BAD" || true)"\n',
        encoding="utf-8", newline="\n")
    done = subprocess.run([bash, script.as_posix(), tmp_path.as_posix()], capture_output=True,
                          text=True, encoding="utf-8", timeout=60)
    assert not list(tmp_path.glob("PWNED*")), "a name in .env.local was evaluated as shell"
    assert done.returncode == 0, done.stdout + done.stderr
    assert "command not found" not in done.stderr and "not a valid identifier" not in done.stderr
    assert "ordinary=fine" in done.stdout and "badnames=0" in done.stdout, done.stdout


def _shell_case_list(path: Path, subject: str) -> tuple[set[str], set[str]]:
    match = re.search(r'case "[^\n]*?%s[^\n]*?" in\n\s+(\S+)\)' % re.escape(subject), _text(path))
    assert match, f"{path.name} lost the list of names it leaves out"
    patterns = match.group(1).split("|")
    return ({p for p in patterns if not p.endswith("*")}, {p[:-1] for p in patterns if p.endswith("*")})


def _powershell_lists(path: Path) -> tuple[set[str], set[str]]:
    text = _text(path)
    out = []
    for variable in ("refusedExact", "refusedPrefixes"):
        match = re.search(r"\$%s\s*=\s*@\(([^)]*)\)" % variable, text)
        assert match, f"{path.name} lost ${variable}"
        out.append(set(re.findall(r"'([^']+)'", match.group(1))))
    return out[0], out[1]


def test_all_five_loaders_leave_out_exactly_the_same_names():
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location("g48_env_list", ENV_PY))
    module.__spec__.loader.exec_module(module)
    expected = (set(module.REFUSED_NAMES), set(module.REFUSED_PREFIXES))
    assert expected[0] and expected[1]
    assert _shell_case_list(INSTALL_SH, "$upper") == expected
    assert _shell_case_list(LAUNCH_SH, "$name") == expected
    assert _powershell_lists(LAUNCH_PS1) == expected
    assert _powershell_lists(OPEN_UI_PS1) == expected


def test_the_install_notes_powershell_loader_leaves_out_the_same_names():
    """release/INSTALL.md gives Windows testers a one-line loader of its own;
    it set any name, PATH included, before this."""
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location("g48_env_doc", ENV_PY))
    module.__spec__.loader.exec_module(module)
    notes = _text(ROOT / "release" / "INSTALL.md")
    line = next(ln for ln in notes.splitlines() if ln.startswith("Get-Content .env.local"))
    match = re.search(r"-notmatch '\^\(([^)]*)\)=\|\^\(([^)]*)\)'", line)
    assert match, "the one-line loader no longer filters names"
    exact = set(re.sub(r"PS\[1-4\]", "PS1|PS2|PS3|PS4", match.group(1)).split("|"))
    assert exact == set(module.REFUSED_NAMES)
    assert set(match.group(2).split("|")) == set(module.REFUSED_PREFIXES)
    assert "leave out a name that changes how programs start" in notes


def test_a_name_is_refused_by_the_python_list_without_regard_to_case():
    module = _env_module(Path("."))
    for name in ("PATH", "path", "Path", "pythonpath", "LD_PRELOAD", "ld_preload", "BASH_ENV", "Ps4",
                 "DOCKER_CONFIG", "docker_host", "COMPOSE_FILE", "Compose_Project_Name", "GIT_SSH_COMMAND",
                 "git_dir", "PIP_INDEX_URL", "pip_require_virtualenv", "NODE_OPTIONS", "node_path",
                 "PSModulePath", "PSMODULEPATH", "psmodulepath"):
        assert module.is_refused_name(name), name
    for name in ("NOCTORNAL_TOTP_KEK", "DATABASE_URL", "PATHOLOGY", "HOMEPAGE", "ENVIRONMENT",
                 "SMTP_HOST", "REDIS_URL",
                 # A prefix is the word and the underscore: a name that only starts alike is a setting.
                 "DOCKERIZED", "GITHUB_NOTE", "NODEPOOL", "PIPELINE", "COMPOSERS", "PSMODULEPATHS"):
        assert not module.is_refused_name(name), name
