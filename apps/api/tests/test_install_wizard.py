"""The install wizard and release/START-HERE.md, held to what they say.

## Why this file exists

The beta is "a usable product with a simple install, and simple instructions
on how to install". The installers became a wizard of eight numbered steps:
a look at the computer that changes nothing, the account made BEFORE the API
starts on Windows as on Linux (the one-time password used to scroll off the
screen under uvicorn's log, release finding R8), a fictional demo case, and a
closing card. Nothing here runs the real installers: they bind ports 5432,
6379, 9000 and 1025. What can be held without running them is held here:

* the logic that decides, as pure functions of their arguments, run in bash
  and (where PowerShell exists) in PowerShell, so that "never prompt when
  stdin is not a terminal" is a result and not a promise;
* the text of both installers: the step numbering, the flags, the order of
  account, wait and start, the closing card;
* that both installers and both start scripts parse;
* START-HERE.md: one page, no dashes, every command and message in it real.

The older checks stay where they were (`test_install_copy.py`,
`test_script_invariants.py`): this file adds, it does not relax.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_g48_install_env_data import ENV_PY, _bash, _powershell_lists
from test_install_copy import _printed_lines
from test_server_copy_no_dashes import DASHES, FAKE_DASH
from test_server_copy_no_lazy_plurals import HEDGE

ROOT = Path(__file__).resolve().parents[3]
RELEASE = ROOT / "release"
INSTALL_SH = RELEASE / "install.sh"
INSTALL_PS1 = RELEASE / "install.ps1"
START_SH = RELEASE / "start.sh"
START_PS1 = RELEASE / "start.ps1"
START_HERE = RELEASE / "START-HERE.md"
INSTALL_MD = RELEASE / "INSTALL.md"
RELEASE_README = RELEASE / "README.md"
README = ROOT / "README.md"
SCRIPTS = ROOT / "scripts"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _code(path: Path) -> str:
    """The lines a reader meets or the shell runs: everything but comments."""
    return "\n".join(line for _, line in _printed_lines(path))


# ---------------------------------------------------------------------------
# The files parse, and keep their line endings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", (INSTALL_SH, START_SH), ids=lambda p: p.name)
def test_the_shell_files_are_lf_and_parse(path: Path):
    assert b"\r" not in path.read_bytes(), f"{path.name} has CR bytes: a CRLF shebang does not run"
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    done = subprocess.run([bash, "-n", path.as_posix()], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("path", (INSTALL_PS1, START_PS1, START_HERE), ids=lambda p: p.name)
def test_the_windows_side_files_do_not_mix_line_endings(path: Path):
    """The working tree here is CRLF and CI's is LF; either is fine, a mix is
    not (a here-string split on a lone line feed leaves a stray CR)."""
    raw = path.read_bytes()
    crlf, lf = raw.count(b"\r\n"), raw.count(b"\n")
    assert crlf in (0, lf), (path.name, crlf, lf)


if POWERSHELL:
    @pytest.mark.parametrize("path", (INSTALL_PS1, START_PS1), ids=lambda p: p.name)
    def test_the_powershell_files_parse(path: Path):
        """The parser, not a run: the installer is never started here."""
        script = (
            "$e=$null;$t=$null;"
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{path}',[ref]$t,[ref]$e);"
            "if($e.Count){$e|ForEach-Object{\"line $($_.Extent.StartLineNumber): $($_.Message)\"};exit 1}")
        done = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script],
                              capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stdout + done.stderr


def test_the_installers_are_ascii_where_a_reader_meets_them():
    """Windows PowerShell 5 reads the file as the ANSI code page: a non-ASCII
    character in a printed line arrives as mojibake."""
    offenders = [(n, line.strip()[:80]) for n, line in _printed_lines(INSTALL_PS1)
                 if any(ord(c) > 127 for c in line)]
    assert not offenders, offenders
    start = [line for _, line in _printed_lines(START_PS1) if any(ord(c) > 127 for c in line)]
    assert not start, start


# ---------------------------------------------------------------------------
# Eight numbered steps, counted by the script itself
# ---------------------------------------------------------------------------

def test_install_sh_has_eight_numbered_steps_and_says_so():
    text = _read(INSTALL_SH)
    assert re.search(r"(?m)^STEP_TOTAL=8$", text)
    steps = re.findall(r"(?m)^step '([^']+)'", text)
    assert len(steps) == 8, steps
    assert steps[0] == "Checking your computer" and steps[-1] == "Starting the API"
    # The heading says "Step N of M", counted by the function.
    assert "'\\n  %sStep %d of %d: %s%s\\n' \"$C_CYAN\" \"$STEP_NO\" \"$STEP_TOTAL\"" in text


def test_install_ps1_has_eight_numbered_steps_and_says_so():
    text = _read(INSTALL_PS1)
    assert re.search(r"(?m)^\$script:StepTotal = 8$", text)
    steps = re.findall(r"(?m)^Write-Step '([^']+)'", text)
    assert len(steps) == 8, steps
    assert steps[0] == "Checking your computer" and steps[-1] == "Starting the API"
    assert 'Step $($script:StepNo) of $($script:StepTotal): $Text' in text


def test_the_two_installers_name_their_steps_alike():
    sh = re.findall(r"(?m)^step '([^']+)'", _read(INSTALL_SH))
    ps = re.findall(r"(?m)^Write-Step '([^']+)'", _read(INSTALL_PS1))
    assert sh == ps, (sh, ps)


def test_step_one_only_looks_and_reports_what_it_found_before_anything_changes():
    """The summary (system, Python, Docker, port) is printed in step 1, before
    the first thing that writes: the virtual environment in step 2."""
    sh = _read(INSTALL_SH)
    one, two = sh.index("step 'Checking your computer'"), sh.index("step 'Building the Python environment'")
    body = sh[one:two]
    for label in ("system:", "Python:", "Docker:", "Port:"):
        assert label in body, label
    assert "Nothing on your computer has been changed" in body
    assert 'describe_os' in body and "COMPOSE_VERSION" in body
    assert "mkdir" not in body and "rm -rf" not in body and "pip install" not in body
    ps = _read(INSTALL_PS1)
    one, two = ps.index("Write-Step 'Checking your computer'"), ps.index("Write-Step 'Building the Python environment'")
    body = ps[one:two]
    for label in ("system:", "Python:", "Docker:", "Port:"):
        assert label in body, label
    assert "Nothing on your computer has been changed" in body
    assert "Remove-Item" not in body and "New-Item" not in body


def test_the_port_is_checked_in_step_one_in_both_installers():
    sh = _read(INSTALL_SH)
    assert sh.index('/dev/tcp/127.0.0.1/$PORT') < sh.index("step 'Building the Python environment'")
    assert sh.count('stop_with "port $PORT is already in use."') == 1
    ps = _read(INSTALL_PS1)
    assert ps.index("Test-PortInUse -Number $Port") < ps.index("Write-Step 'Building the Python environment'")
    assert ps.count('"port $Port is already in use."') == 1
    # --skip-launch / -SkipLaunch starts nothing, so a busy port does not stop it.
    assert "-eq 1 && $SKIP_LAUNCH -eq 0" in sh
    assert "$portBusy -and -not $SkipLaunch" in ps


def _sh_string(text: str, i: int) -> tuple[str, int]:
    """One shell word in quotes, after any spaces and line continuations."""
    while text[i] in " \t\\\n":
        i += 1
    quote = text[i]
    assert quote in "\"'", text[i:i + 40]
    j = i + 1
    while text[j] != quote:
        j += 2 if quote == '"' and text[j] == "\\" else 1
    return text[i + 1:j], j + 1


def _ps_first_line(text: str, i: int) -> str:
    """The first line of the fix a Stop-With call passes: after the problem."""
    quote = text[i]
    j = i + 1
    while True:
        if text[j] == quote:
            if text[j + 1] == quote:
                j += 2
                continue
            break
        j += 2 if quote == '"' and text[j] == "`" else 1
    i = j + 1
    while text[i] in " \t`\n":
        i += 1
    if text[i] == "@":
        start = text.index("\n", i) + 1
        return text[start:text.index("\n\n", start)]
    quote = text[i]
    j = i + 1
    while text[j] != quote:
        j += 1
    return text[i + 1:j].replace("`n", "\n").split("\n\n")[0]


def _fix_first_lines(path: Path) -> list[str]:
    text = _read(path)
    found = []
    if path.suffix == ".sh":
        for m in re.finditer(r"\bstop_with\b(?!\(\))", text):
            _, at = _sh_string(text, m.end())
            fix, _ = _sh_string(text, at)
            found.append(fix.split("\n\n")[0])
    else:
        for m in re.finditer(r"\bStop-With\b(?! \{)", text):
            at = m.end()
            while text[at] == " ":
                at += 1
            if text[at] not in "'\"":
                continue
            found.append(_ps_first_line(text, at))
    return found


@pytest.mark.parametrize("path", (INSTALL_SH, INSTALL_PS1), ids=lambda p: p.name)
def test_every_failure_opens_with_a_sentence_that_says_what_to_do(path: Path):
    """"Cannot continue: <what>" is followed by "What to do:", and what comes
    first there is one full sentence that tells the person what to do: not a
    description of the machine, and not a bare command."""
    paragraphs = _fix_first_lines(path)
    assert len(paragraphs) >= 14, (path.name, len(paragraphs))
    bad = []
    for paragraph in paragraphs:
        flat = " ".join(paragraph.split())
        sentence = re.match(r"(.+?[.:])(\s|$)", flat)
        if not sentence or flat.split()[0] in {"The", "This", "It", "install.sh", "install.ps1"}:
            bad.append(flat[:80])
    assert not bad, (path.name, bad)


# ---------------------------------------------------------------------------
# The flags
# ---------------------------------------------------------------------------

def test_install_sh_takes_demo_no_demo_and_open_and_every_older_flag():
    text = _read(INSTALL_SH)
    header = "\n".join(line for line in text.splitlines()[:40] if line.startswith("#"))
    for flag in ("--demo", "--no-demo", "--open", "--port 8001", "--skip-launch",
                 "--with-telegram", "--with-yara"):
        assert f"./release/install.sh {flag}" in header, flag
    for arm in ("--demo)", "--no-demo)", "--open)", "--port)", "--skip-launch)",
                "--with-telegram)", "--with-yara)", "--production-secrets)", "--dir)"):
        assert f"    {arm}" in text, arm
    assert "choose --demo or --no-demo, not both" in text


def test_install_ps1_takes_demo_nodemo_and_open_and_every_older_parameter():
    text = _read(INSTALL_PS1)
    for name in ("Demo", "NoDemo", "Open", "SkipLaunch", "WithTelegram", "WithYara",
                 "ProductionSecrets"):
        assert f"[switch] ${name}" in text, name
        assert f".PARAMETER {name}" in text, name
    assert "[int]    $Port = 8000" in text and "[string] $ProductionDir" in text
    assert "choose -Demo or -NoDemo, not both" in text


# ---------------------------------------------------------------------------
# What is decided, run
# ---------------------------------------------------------------------------

def _shell_function(name: str) -> str:
    match = re.search(rf"(?ms)^{name}\(\) \{{\n.*?^\}}\n", _read(INSTALL_SH))
    assert match, f"install.sh no longer defines {name}"
    return match.group(0)


def _bash_run(tmp_path: Path, names: tuple[str, ...], calls: list[str]) -> list[str]:
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    script = tmp_path / "decide.sh"
    script.write_text("set -euo pipefail\n" + "".join(_shell_function(n) for n in names) +
                      "\n".join(calls) + "\n", encoding="utf-8", newline="\n")
    done = subprocess.run([bash, script.as_posix()], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.split()


#: (mode, interactive, fresh) -> what to do about the demo.
_DEMO_TABLE = [
    # No terminal: never ask. Only --demo loads it.
    ("", 0, 1, "skip"), ("", 0, 0, "skip"), ("yes", 0, 1, "load"), ("yes", 0, 0, "load"),
    ("no", 0, 1, "skip"),
    # A terminal: ask only the person who has just made their first account.
    ("", 1, 1, "ask"), ("", 1, 0, "skip"), ("yes", 1, 1, "load"), ("no", 1, 1, "skip"),
    ("yes", 1, 0, "load"), ("no", 1, 0, "skip"),
]

#: (force, interactive, desktop) -> what to do about the browser.
_OPEN_TABLE = [
    (0, 0, 0, "skip"), (0, 1, 0, "skip"), (1, 0, 0, "skip"), (1, 1, 0, "skip"),
    (0, 0, 1, "skip"), (0, 1, 1, "ask"), (1, 0, 1, "open"), (1, 1, 1, "open"),
]

_ANSWERS = [("", "yes"), ("y", "yes"), ("Y", "yes"), ("yes", "yes"), ("n", "no"),
            ("N", "no"), ("no", "no"), ("x", "no")]


def test_the_demo_decision_never_asks_without_a_terminal(tmp_path):
    calls = [f'decide_demo "{m}" {i} {f}' for m, i, f, _ in _DEMO_TABLE]
    got = _bash_run(tmp_path, ("decide_demo",), calls)
    assert got == [want for *_, want in _DEMO_TABLE]
    assert not any(want == "ask" for m, i, f, want in _DEMO_TABLE if i == 0)


def test_the_browser_decision_needs_a_desktop_and_a_terminal_or_the_flag(tmp_path):
    calls = [f'decide_open {a} {b} {c}' for a, b, c, _ in _OPEN_TABLE]
    got = _bash_run(tmp_path, ("decide_open",), calls)
    assert got == [want for *_, want in _OPEN_TABLE]
    assert not any(want == "ask" for a, i, d, want in _OPEN_TABLE if i == 0)


def test_enter_takes_the_default_yes_in_bash(tmp_path):
    got = _bash_run(tmp_path, ("answer_is_yes",), [f'answer_is_yes "{a}"' for a, _ in _ANSWERS])
    assert got == [want for _, want in _ANSWERS]


def _ps_function(name: str) -> str:
    match = re.search(rf"(?ms)^function {re.escape(name)} \{{\n.*?^\}}\n", _read(INSTALL_PS1))
    assert match, f"install.ps1 no longer defines {name}"
    return match.group(0)


def _bool(flag: int) -> str:
    return "$true" if flag else "$false"


if POWERSHELL:
    def _ps_run(tmp_path: Path, names: tuple[str, ...], calls: list[str]) -> list[str]:
        script = tmp_path / "decide.ps1"
        script.write_text("".join(_ps_function(n) for n in names) + "\n".join(calls) + "\n",
                          encoding="utf-8")
        done = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
        assert done.returncode == 0, done.stdout + done.stderr
        return done.stdout.split()

    def test_install_ps1_decides_the_demo_as_install_sh_does(tmp_path):
        mode = {"": "''", "yes": "'yes'", "no": "'no'"}
        calls = [f"Get-DemoDecision -Mode {mode[m]} -Interactive {_bool(i)} -Fresh {_bool(f)}"
                 for m, i, f, _ in _DEMO_TABLE]
        assert _ps_run(tmp_path, ("Get-DemoDecision",), calls) == [w for *_, w in _DEMO_TABLE]

    def test_install_ps1_decides_the_browser_as_install_sh_does(tmp_path):
        calls = [f"Get-OpenDecision -Force {_bool(a)} -Interactive {_bool(b)} -Desktop {_bool(c)}"
                 for a, b, c, _ in _OPEN_TABLE]
        assert _ps_run(tmp_path, ("Get-OpenDecision",), calls) == [w for *_, w in _OPEN_TABLE]

    def test_install_ps1_takes_enter_as_yes(tmp_path):
        calls = [f"if (Test-AnswerYes '{a}') {{ 'yes' }} else {{ 'no' }}" for a, _ in _ANSWERS]
        assert _ps_run(tmp_path, ("Test-AnswerYes",), calls) == [w for _, w in _ANSWERS]
else:
    def test_install_ps1_carries_the_same_decision_functions():
        text = _read(INSTALL_PS1)
        for name in ("Get-DemoDecision", "Get-OpenDecision", "Test-AnswerYes"):
            assert f"function {name}" in text, name


def test_standard_input_decides_whether_a_person_is_there_in_both_installers():
    assert "if [[ -t 0 ]]; then INTERACTIVE=1; fi" in _read(INSTALL_SH)
    assert "[Console]::IsInputRedirected" in _read(INSTALL_PS1)


def test_install_sh_asks_nothing_but_the_account_questions_outside_a_guard():
    """Five `read`s, and each behind the decision that says a person is there:
    the two the account has always had, the Enter that waits for the saved
    password, the demo question and the browser question."""
    text = _read(INSTALL_SH)
    reads = [m.start() for m in re.finditer(r"(?m)^\s*read -r \w+", text)]
    assert len(reads) == 5, len(reads)
    assert all(line.rstrip().endswith("|| true") for line in text.splitlines()
               if line.strip().startswith("read -r")), "a read at end of input must not end the script"
    saved = text.index("read -r _saved")
    assert text.rindex("if [[ $INTERACTIVE -eq 1 ]]; then", 0, saved) > text.index("scripts/bootstrap.py create-user")
    demo = text.index("read -r DEMO_ANSWER")
    assert text.rindex('if [[ "$DEMO_DECISION" == "ask" ]]; then', 0, demo) > text.index("step 'Loading the demo case")
    browser = text.index("read -r OPEN_ANSWER")
    assert text.rindex('if [[ "$OPEN_DECISION" == "ask" ]]; then', 0, browser) > text.index("step 'Starting the API'")


def test_install_ps1_asks_nothing_but_the_account_questions_outside_a_guard():
    text = _read(INSTALL_PS1)
    waits = [m.start() for m in re.finditer(r"Read-Line 'Press Enter when you have saved them'", text)]
    assert len(waits) == 1
    assert text.rindex("if ($script:Interactive) {", 0, waits[0]) > text.index("create-user --email")
    demo = text.index("Read-Line 'Load the synthetic demo case so there is something to explore? [Y/n]'")
    assert text.rindex("if ($demoDecision -eq 'ask') {", 0, demo) > text.index("Write-Step 'Loading the demo case")
    browser = text.index("Read-Line 'Open the console in your browser when it is ready? [Y/n]'")
    assert text.rindex("if ($openDecision -eq 'ask') {", 0, browser) > text.index("Write-Step 'Starting the API'")


def test_the_demo_question_is_the_one_the_brief_words():
    for path in (INSTALL_SH, INSTALL_PS1):
        assert ("Load the synthetic demo case so there is something to explore? [Y/n]"
                in _read(path)), path.name


# ---------------------------------------------------------------------------
# The account before the API, and a wait for the password (R8)
# ---------------------------------------------------------------------------

def test_install_ps1_makes_the_account_before_it_starts_the_api_and_waits():
    code = _code(INSTALL_PS1)
    account = code.index("create-user --email")
    wait = code.index("Read-Line 'Press Enter when you have saved them'")
    api = code.index("-m uvicorn")
    assert account < wait < api
    # And it no longer hands the whole job to launch.ps1, whose log was the R8 cause.
    assert not re.search(r"&\s*powershell[^\n]*launch\.ps1", code), "install.ps1 hands off to launch.ps1 again"
    assert "-File (Join-Path $RepoRoot 'scripts\\launch.ps1')" not in code


def test_install_sh_makes_the_account_before_it_starts_the_api_and_waits():
    code = _code(INSTALL_SH)
    account = code.index("scripts/bootstrap.py create-user")
    wait = code.index("read -r _saved")
    api = code.index('exec "$VENV/bin/uvicorn"')
    assert account < wait < api


@pytest.mark.parametrize("path", (INSTALL_SH, INSTALL_PS1), ids=lambda p: p.name)
def test_a_failed_account_stops_the_install_with_a_sentence(path: Path):
    assert "the account could not be made." in _read(path)


@pytest.mark.parametrize("path", (INSTALL_SH, INSTALL_PS1), ids=lambda p: p.name)
def test_a_missing_name_or_email_still_skips_the_account_and_says_how_to_make_it_later(path: Path):
    text = _read(path)
    assert "Skipped: both an email and a display name are needed." in text
    assert "create-user" in text[text.index("Skipped: both an email"):][:400]


# ---------------------------------------------------------------------------
# The demo case is the synthetic TLP:CLEAR one, and the installer says so
# ---------------------------------------------------------------------------

def _bootstrap():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import bootstrap
    return bootstrap


@pytest.mark.parametrize("path", (INSTALL_SH, INSTALL_PS1), ids=lambda p: p.name)
def test_the_demo_is_the_synthetic_clear_network_and_called_fictional(path: Path):
    text = _read(path)
    assert "OP-LATTICEWORK-26" in text
    assert "--classification CLEAR" in text
    assert "demo-network" in text and "demo-case" not in _code(path)
    shown = " ".join(line for _, line in _printed_lines(path))
    assert "fictional" in shown.lower() and "TLP:CLEAR" in shown
    assert "holds nothing real" in shown


def test_the_demo_command_is_one_bootstrap_accepts_and_its_default_code_matches():
    bootstrap = _bootstrap()
    args = bootstrap._build_parser().parse_args(
        ["demo-network", "--owner-email", "you@example.org", "--code", "OP-LATTICEWORK-26",
         "--classification", "CLEAR"])
    assert args.func is bootstrap.cmd_demo_network and args.classification == "CLEAR"
    assert 'args.code or "OP-LATTICEWORK-26"' in _read(SCRIPTS / "bootstrap.py")


# ---------------------------------------------------------------------------
# The closing card
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,start", [(INSTALL_SH, "start:    next time, run: cd"),
                                        (INSTALL_PS1, "start:    next time, from")],
                         ids=lambda v: getattr(v, "name", "start"))
def test_the_closing_card_says_everything_a_first_time_user_needs(path: Path, start: str):
    text = _read(path)
    card = text[text.index("You are ready."):]
    shown = _flat(" ".join(line for _, line in _printed_lines(path)))
    tail = _flat(card)
    assert "console:" in tail and "/ui/" in text
    assert ("$consoleUrl" in tail) if path.suffix == ".ps1" else ("/ui/" in tail)
    if path.suffix == ".ps1":
        assert '$consoleUrl = "http://127.0.0.1:$Port/ui/"' in text
    assert "sign in:" in tail and "six-digit code from your authenticator app" in tail
    assert start in card
    assert ("release/start.sh" if path.suffix == ".sh" else "release\\start.ps1") in card
    assert "Ctrl-C" in card or "Ctrl+C" in card
    assert "docker compose -f infra/docker-compose.yml down" in card
    assert "release/START-HERE.md" in card or "release\\START-HERE.md" in card
    assert "MANUAL.md" in card
    # One short sentence about the beta, and the legal pointer.
    assert "This is a beta: use it on synthetic or published, non-personal data only." in tail
    assert 'Real case material needs legal review first (docs/16, "Read this before you hold anything").' in tail
    assert "You are ready." in shown


def test_the_docs16_heading_the_card_names_exists():
    legal = _read(ROOT / "docs" / "16-legal-and-external.md")
    assert re.search(r"(?m)^## Read this before you hold anything$", legal)


def test_the_browser_is_opened_only_once_the_api_answers_and_never_by_force_without_a_desktop():
    sh = _read(INSTALL_SH)
    assert "open_when_up" in sh and 'open_when_up "http://127.0.0.1:$PORT/ui/" >/dev/null 2>&1 &' in sh
    assert sh.index("open_when_up \"http") < sh.index('exec "$VENV/bin/uvicorn"')
    assert 'xdg-open "$url"' in sh and 'open "$url"' in sh
    ps = _read(INSTALL_PS1)
    assert "Start-Job" in ps and "TcpClient" in ps and "Start-Process $jobUrl" in ps
    assert ps.index("Start-Job") < ps.index("-m uvicorn")


# ---------------------------------------------------------------------------
# .env.local stays data in the Windows installer too
# ---------------------------------------------------------------------------

def test_install_ps1_leaves_out_the_same_names_as_every_other_loader():
    import importlib.util
    spec = importlib.util.spec_from_file_location("g51_env_list", ENV_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert _powershell_lists(INSTALL_PS1) == (set(module.REFUSED_NAMES), set(module.REFUSED_PREFIXES))
    code = _code(INSTALL_PS1)
    assert "Import-EnvLocal -Path $EnvLocal" in code
    # Read as data: no dot-sourcing and no Invoke-Expression of the file.
    assert not re.search(r"(?i)invoke-expression|\biex\b|\.\s+\$EnvLocal", code)


def test_install_ps1_applies_the_loopback_defaults_where_the_file_is_silent():
    text = _read(INSTALL_PS1)
    block = text[text.index("$defaults = [ordered]@{"):][:700]
    for want in ("@127.0.0.1:5432/noctornal", "redis://127.0.0.1:6379/0", "127.0.0.1:9000"):
        assert want in block, want
    assert "localhost" not in block


# ---------------------------------------------------------------------------
# The start scripts do exactly one thing
# ---------------------------------------------------------------------------

def test_start_sh_runs_launch_sh_and_nothing_else():
    code = [ln for ln in _read(START_SH).splitlines() if ln.strip() and not ln.strip().startswith("#")]
    runs = [ln for ln in code if "launch.sh" in ln]
    assert runs == ['exec bash "$HERE/../scripts/launch.sh" "$@"'], runs
    assert not any(w in " ".join(code) for w in ("docker", "alembic", "uvicorn", "pip install", "rm -"))


def test_start_ps1_runs_launch_ps1_and_nothing_else():
    code = _code(START_PS1)
    assert "scripts\\launch.ps1" in code and "-ExecutionPolicy" in code and "Bypass" in code
    assert not any(w in code for w in ("docker", "alembic", "uvicorn", "pip install", "Remove-Item"))
    assert "[switch] $SkipDocker" in code and "[int]    $Port = 8000" in code


def test_start_sh_help_prints_its_header_and_does_not_start_anything():
    bash = _bash()
    if bash is None:
        pytest.skip("no bash")
    done = subprocess.run([bash, START_SH.as_posix(), "--help"], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)
    assert done.returncode == 0, done.stderr
    assert "bash release/start.sh --port 8001" in done.stdout
    assert "set -" not in done.stdout


@pytest.mark.parametrize("path", (START_SH, START_PS1), ids=lambda p: p.name)
def test_the_start_scripts_print_no_dash_and_no_bracketed_plural(path: Path):
    printed = _printed_lines(path)
    assert not [(n, ln) for n, ln in printed if any(d in ln for d in DASHES) or FAKE_DASH.search(ln)]
    assert not [(n, ln) for n, ln in printed if HEDGE.search(ln)]


@pytest.mark.parametrize("path", (INSTALL_SH, INSTALL_PS1), ids=lambda p: p.name)
def test_the_wizard_text_prints_no_dash_and_no_bracketed_plural(path: Path):
    """The older tests hold this for every printed line already; stated here
    for the lines this change added, so a failure names the wizard."""
    printed = _printed_lines(path)
    assert not [(n, ln.strip()) for n, ln in printed if any(d in ln for d in DASHES) or FAKE_DASH.search(ln)]
    assert not [(n, ln.strip()) for n, ln in printed if HEDGE.search(ln)]


def test_the_packager_requires_the_new_files():
    text = _read(SCRIPTS / "package_release.ps1")
    for name in ("release/START-HERE.md", "release/start.sh", "release/start.ps1"):
        assert f"'{name}'" in text, name
    assert "start at release/START-HERE.md" in text


# ---------------------------------------------------------------------------
# START-HERE.md: one page a non-expert can follow
# ---------------------------------------------------------------------------

def test_start_here_is_one_page():
    text = _read(START_HERE)
    assert len(text.splitlines()) <= 130, len(text.splitlines())
    assert len(text.split()) <= 1300, len(text.split())


def test_start_here_has_the_sections_the_brief_asks_for():
    headings = re.findall(r"(?m)^#{1,3} (.+)$", _read(START_HERE))
    for want in ("What you need", "Install in three steps", "Your first sign-in",
                 "Load the demo case", "The first five things to try", "What the beta is",
                 "Start, stop, update, uninstall", "Something went wrong"):
        assert want in headings, (want, headings)


def test_start_here_prints_no_dash_and_no_bracketed_plural():
    text = _read(START_HERE)
    assert not any(d in text for d in DASHES), "an em or en dash"
    lines = text.splitlines()
    assert not [ln for ln in lines if FAKE_DASH.search(ln)]
    assert not [ln for ln in lines if HEDGE.search(ln)]


def test_start_here_gives_the_real_install_commands():
    text = _read(START_HERE)
    assert "powershell -ExecutionPolicy Bypass -File .\\release\\install.ps1" in text
    assert "bash release/install.sh" in text
    assert "bash release/start.sh" in text
    assert "powershell -ExecutionPolicy Bypass -File .\\release\\start.ps1" in text
    assert "--port 8001" in text and "-Port 8001" in text and "--open" in text and "-Open" in text
    assert "docker compose -f infra/docker-compose.yml down" in text
    assert "docker compose -f infra/docker-compose.yml down -v" in text
    # The commands it prints exist where it says: the project folder has them.
    assert (ROOT / "start.cmd").is_file() and "start.cmd" in text
    assert (ROOT / "infra" / "docker-compose.yml").is_file()


def test_start_here_demo_command_is_the_one_the_installer_prints():
    text = _read(START_HERE)
    command = next(ln.strip() for ln in text.splitlines() if "bootstrap.py demo-network" in ln)
    args = _bootstrap()._build_parser().parse_args(command.split()[2:])
    assert (args.code, args.classification) == ("OP-LATTICEWORK-26", "CLEAR")
    assert "fictional" in text.lower()


def test_start_here_diagnose_command_is_one_bootstrap_accepts():
    text = _read(START_HERE)
    command = re.search(r"`(\.venv/bin/python scripts/bootstrap\.py totp-diagnose[^`]*)`", text).group(1)
    args = _bootstrap()._build_parser().parse_args(command.split()[2:])
    assert args.func is _bootstrap().cmd_totp_diagnose


def test_start_here_names_five_problems_and_quotes_messages_the_installers_print():
    text = _read(START_HERE)
    table = text[text.index("## Something went wrong"):]
    rows = [ln for ln in table.splitlines() if ln.startswith("| ") and not ln.startswith("| You see")
            and not ln.startswith("|---")]
    assert len(rows) == 5, rows
    sh, ps = _read(INSTALL_SH), _read(INSTALL_PS1)
    # (what the page quotes, what each installer prints in its place)
    for quoted, in_sh, in_ps in (
            ("Python 3.12 or newer was not found",
             "Python 3.12 or newer was not found", "Python 3.12 or newer was not found"),
            ("Docker is installed but the engine is not running",
             "Docker is installed but the engine is not reachable",
             "Docker is installed but the engine is not running"),
            ("port 8000 is already in use",
             'port $PORT is already in use', 'port $Port is already in use'),
            ("docker compose up failed", "docker compose up failed", "docker compose up failed"),
            ("in use by another program",
             "in use by another program", "in use by another program")):
        assert quoted in " ".join(rows), quoted
        assert in_sh in sh and in_ps in ps, quoted
    assert 'not reachable' in " ".join(rows)


def test_start_here_links_resolve_and_the_other_documents_point_at_it():
    text = _read(START_HERE)
    for target in re.findall(r"\]\(([^)\s#]+)(?:#[^)\s]*)?\)", text):
        if target.startswith(("http://", "https://")):
            continue
        assert (RELEASE / target).resolve().exists(), target
    assert "](START-HERE.md)" in _read(INSTALL_MD)
    assert "](START-HERE.md)" in _read(RELEASE_README)
    assert "](release/START-HERE.md)" in _read(README)
    # Close to the top of the install section, as the pointer.
    readme = _read(README)
    assert readme.index("release/START-HERE.md") < readme.index("### Prerequisites")


def test_install_md_no_longer_says_windows_hands_off_or_prints_the_command():
    text = _flat(_read(INSTALL_MD))
    assert "hands off to `launch.ps1`, which prints a banner" not in text
    assert "(on Windows it prints the command that does" not in text
    assert "R8, fixed" in text
    assert "before the API starts" in text
    readme = _flat(_read(README))
    assert "on Windows it prints the `create-user` command to run instead" not in readme
    assert "installed on Windows, where the installer prints this command" not in readme


def test_install_md_documents_the_new_flags_and_the_start_scripts():
    text = _read(INSTALL_MD)
    for flag in ("`--demo`", "`-Demo`", "`--no-demo`", "`-NoDemo`", "`--open`", "`-Open`"):
        assert flag in text, flag
    assert "bash release/start.sh" in text and "release\\start.ps1" in text
    # Older tests hold the quoted refusal and the no-opening phrases; keep them true.
    assert '**"port 8000 is already in use"**' in text
