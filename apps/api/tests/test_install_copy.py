"""What the installers, launchers and scripts print, and what the install
documents say, held to what the software does.

## Why this file exists

The Alpha 6 pre-release check (2026-09-23) installed the release candidate
on a clean Ubuntu machine, read every line the installer printed, and
followed the README and `release/INSTALL.md` as written. Nothing stopped
the install, and most of what it found was words: the first command the
installer suggested failed on Linux, the README asked for an account the
installer had already made, the legal gate was four items in one place and
five in another, `--help` printed a line of code, a launcher named the
ports of services removed months ago, the install notes quoted a
port-in-use message the Linux installer never printed and a test total two
releases old, and printed copy outside the server still carried the dash
the server copy tests refuse. And nothing told a new install that its first
account holds no Security Officer role, which a blocking readiness check
requires.

Each check below holds one of those to the tree, statically where the
thing is a script nothing here can run, and by running it where that is
safe (the Alembic refusal).

The dash rule is the server copy rule (`test_server_copy_no_dashes.py`),
applied to what these programs print: every string literal a reader could
meet in `scripts/*.py`, the part of a module docstring that `argparse`
prints as `--help`, and every line of the two installers and two launchers
that is not a comment.

Pure: no database, no object store. One test runs Alembic in a subprocess
with no DATABASE_URL, which refuses before it connects to anything.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from test_server_copy_no_dashes import (
    DASHES,
    FAKE_DASH,
    SQL_CALL,
    _statement_strings,
    dashed_literals,
    without_line_comments,
)
from test_server_copy_no_lazy_plurals import HEDGE

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
INSTALL_SH = ROOT / "release" / "install.sh"
INSTALL_PS1 = ROOT / "release" / "install.ps1"
LAUNCH_SH = SCRIPTS / "launch.sh"
LAUNCH_PS1 = SCRIPTS / "launch.ps1"
SHELL_SCRIPTS = (INSTALL_SH, INSTALL_PS1, LAUNCH_SH, LAUNCH_PS1)
INSTALL_MD = ROOT / "release" / "INSTALL.md"
README = ROOT / "README.md"
COMPOSE = ROOT / "infra" / "docker-compose.yml"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _script_files() -> list[Path]:
    found = sorted(SCRIPTS.glob("*.py"))
    assert len(found) > 10, f"only {len(found)} scripts under {SCRIPTS}"
    return found


# ---------------------------------------------------------------------------
# Dashes in what scripts/*.py print
# ---------------------------------------------------------------------------

#: (script, exact literal) -> why it may keep an em or en dash. Keyed on the
#: text, so a sentence cannot shelter under it, and reported as stale once
#: nothing needs it.
_DASH_DATA: dict[tuple[str, str], str] = {
    ("refresh_counters.py", "(0001`\\s*[-\u2013\u2014]\\s*`)(\\d{4})"): (
        "a pattern that must still match a revision range written with "
        "either dash in a document"),
}

#: (script, name) -> (what takes the syntax out, why). `name` is the
#: variable a literal is assigned to, or `function()` for a literal inside
#: that function. Only the syntax is taken out; prose beside it is read.
_HYPHEN_DATA = {
    ("dump_schema.py", "_VOLATILE"): (
        without_line_comments,
        "pg_dump's own SQL comment lines, matched so they can be removed"),
    ("dump_schema.py", "header()"): (
        without_line_comments,
        "the SQL comment block written at the top of db/schema.sql"),
}


def _literals(tree: ast.AST):
    """(literal, in the first argument of `.execute()`, names in scope) for
    every string literal a reader could meet. The server test's reader,
    plus the enclosing function's name, because a script builds more of
    its data inside functions than the server does."""
    skip = _statement_strings(tree)
    found = []

    def visit(node, in_sql: bool, names: frozenset[str]) -> None:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and id(node) not in skip:
                found.append((node, in_sql, names))
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = names | {t.id for t in targets if isinstance(t, ast.Name)}
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names = names | {f"{node.name}()"}
        sql_arg = (node.args[0] if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute)
                   and node.func.attr == SQL_CALL and node.args else None)
        for child in ast.iter_child_nodes(node):
            visit(child, in_sql or child is sql_arg, names)

    visit(tree, False, frozenset())
    return found


def printed_docstring(source: str) -> str:
    """The part of the module docstring `argparse` prints as `--help`: all
    of it for `description=__doc__`, the first piece for
    `description=__doc__.split(sep, 1)[0]`, and nothing when the docstring
    is not the description."""
    tree = ast.parse(source)
    doc = ast.get_docstring(tree, clean=False) or ""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != "description":
                continue
            value = kw.value
            if isinstance(value, ast.Name) and value.id == "__doc__":
                return doc
            if (isinstance(value, ast.Subscript)
                    and isinstance(value.value, ast.Call)
                    and isinstance(value.value.func, ast.Attribute)
                    and value.value.func.attr == "split"
                    and isinstance(value.value.func.value, ast.Name)
                    and value.value.func.value.id == "__doc__"):
                sep = ast.literal_eval(value.value.args[0])
                return doc.split(sep, 1)[0]
    return ""


def _scan_scripts():
    """(dash offenders, hyphen offenders, exemptions used)."""
    dashes, hyphens, used = [], [], set()
    for path in _script_files():
        name = path.name
        source = path.read_text(encoding="utf-8")
        for line, text in dashed_literals(source):
            if (name, text) in _DASH_DATA:
                used.add((name, text))
            else:
                dashes.append((name, line, text[:100]))
        for node, in_sql, names in _literals(ast.parse(source)):
            text = node.value
            if not FAKE_DASH.search(text):
                continue
            if in_sql:
                text = without_line_comments(text)
                used.add(SQL_CALL)
            for scope in sorted(names):
                if (name, scope) in _HYPHEN_DATA:
                    text = _HYPHEN_DATA[name, scope][0](text)
                    used.add((name, scope))
            if FAKE_DASH.search(text):
                hyphens.append((name, node.lineno, node.value[:100]))
        doc = printed_docstring(source)
        for lineno, line in enumerate(doc.split("\n"), 1):
            if any(d in line for d in DASHES):
                dashes.append((name, f"docstring line {lineno}", line.strip()))
            if FAKE_DASH.search(line):
                hyphens.append((name, f"docstring line {lineno}", line.strip()))
    return dashes, hyphens, used


def test_the_docstring_reader_prints_what_argparse_prints():
    whole = '"""One.\n\nTwo."""\nimport argparse\nargparse.ArgumentParser(description=__doc__)\n'
    para = whole.replace("description=__doc__",
                         'description=__doc__.split("\\n\\n", 1)[0]')
    line = whole.replace("description=__doc__",
                         'description=__doc__.split("\\n", 1)[0]')
    own = whole.replace("description=__doc__", 'description="Own words."')
    assert printed_docstring(whole) == "One.\n\nTwo."
    assert printed_docstring(para) == "One."
    assert printed_docstring(line) == "One."
    assert printed_docstring(own) == ""


def test_no_script_prints_an_em_or_en_dash():
    dashes, _, _ = _scan_scripts()
    assert not dashes, (
        "a dash in what a script prints; use a full stop where it joined two "
        "sentences, a comma or colon where it introduced or appended, "
        "parentheses for an aside: " + repr(dashes[:20]))


def test_no_script_fakes_a_dash_with_two_hyphens():
    _, hyphens, _ = _scan_scripts()
    assert not hyphens, (
        "two hyphens standing in for a dash in what a script prints; rewrite "
        "it, or, if the literal is data, add it to _HYPHEN_DATA with the "
        "syntax it is: " + repr(hyphens[:20]))


def test_every_script_exemption_still_lets_something_off():
    """An exemption outliving its literal is a hole for the next one."""
    _, _, used = _scan_scripts()
    stale = [key for key in (*_DASH_DATA, *_HYPHEN_DATA) if key not in used]
    assert not stale, stale


# ---------------------------------------------------------------------------
# Dashes and bracketed plurals in the installers and launchers
# ---------------------------------------------------------------------------

def _printed_lines(path: Path) -> list[tuple[int, str]]:
    """Every line that is not a comment. Strings, heredocs, here-strings
    and PowerShell's `<# ... #>` help block (shown by Get-Help) all count,
    because a reader meets each of them."""
    return [(n, line) for n, line in enumerate(_read(path).split("\n"), 1)
            if not line.strip().startswith("#")]


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_the_installers_and_launchers_print_no_dash(path: Path):
    offenders = [(n, line.strip()) for n, line in _printed_lines(path)
                 if any(d in line for d in DASHES) or FAKE_DASH.search(line)]
    assert not offenders, offenders


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_the_installers_and_launchers_agree_their_plurals(path: Path):
    """The account count carried a bracketed plural; it reads
    `2 user accounts exist` now, and `1 user account exists` for one. The
    hedge is matched with the server plural test's own pattern."""
    offenders = [(n, line.strip()) for n, line in _printed_lines(path)
                 if HEDGE.search(line)]
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# --help prints the usage, and nothing after it
# ---------------------------------------------------------------------------

def _header_comment(text: str) -> str:
    """What the scripts' `awk` prints: the comment lines after the shebang,
    up to the first line that is not a comment, with `# ` taken off."""
    out = []
    for line in text.split("\n")[1:]:
        if not line.startswith("#"):
            break
        out.append(re.sub(r"^# ?", "", line))
    return "\n".join(out)


_HELP_AWK = "awk 'NR == 1 { next } /^#/ { sub(/^# ?/, \"\"); print; next } { exit }' \"$0\""


@pytest.mark.parametrize("path,usage", [
    (INSTALL_SH, "./release/install.sh --port 8001"),
    (LAUNCH_SH, "./scripts/launch.sh [--skip-docker] [--port 8000]"),
], ids=lambda v: getattr(v, "name", "usage"))
def test_help_prints_the_header_and_no_code(path: Path, usage: str):
    """`sed -n '2,20p'` printed one line past the header: `set -euo
    pipefail`, as the last line of the usage text."""
    text = _read(path)
    assert _HELP_AWK in text, f"{path.name} --help no longer reads the header"
    code = "\n".join(line for _, line in _printed_lines(path))
    assert not re.search(r"sed -n '\d+,\d+p'", code), (
        f"{path.name} prints a fixed line range again")
    header = _header_comment(text)
    assert usage in header, header
    assert "set -" not in header and "PORT=" not in header, header


# ---------------------------------------------------------------------------
# install.sh: the messages a new Linux user acts on
# ---------------------------------------------------------------------------

def test_the_debian_advice_updates_the_package_lists_first():
    """On a fresh cloud image `apt install python3.12-venv` answers "has no
    installation candidate" until `apt update` has run."""
    lines = [ln for _, ln in _printed_lines(INSTALL_SH) if "apt install" in ln]
    assert lines, "the Debian advice moved; this test is blind"
    for line in lines:
        assert "apt update && sudo apt install" in line, line


def test_a_port_in_use_is_refused_before_uvicorn_in_the_words_install_md_quotes():
    """install.sh ran every step and then died in uvicorn's `[Errno 98]`,
    while INSTALL.md quoted a message only launch.ps1 printed."""
    sh = _read(INSTALL_SH)
    probe = sh.find('/dev/tcp/127.0.0.1/$PORT')
    refusal = sh.find('stop_with "port $PORT is already in use."')
    launch = sh.find('exec "$VENV/bin/uvicorn"')
    assert -1 < probe < refusal < launch, (probe, refusal, launch)
    assert '"port $Port is already in use"' in _read(LAUNCH_PS1)
    assert '**"port 8000 is already in use"**' in _read(INSTALL_MD)


def _compose_host_ports() -> set[str]:
    ports = set()
    for entries in re.findall(r"(?m)^\s*ports:\s*\[(.*)\]", _read(COMPOSE)):
        for spec in re.findall(r'"([^"]+)"', entries):
            ports.add(spec.split(":")[-2])
    assert len(ports) >= 6, ports
    return ports


@pytest.mark.parametrize("path", (LAUNCH_SH, LAUNCH_PS1), ids=lambda p: p.name)
def test_the_launchers_name_the_ports_the_compose_file_publishes(path: Path):
    """They named 8080 and 4222, OpenFGA's and NATS's, removed in R13, and
    left out Mailpit's 1025."""
    match = re.search(r"a port is already taken \(([\d, ]+)\)", _read(path))
    assert match, f"{path.name} no longer lists the ports"
    named = {p.strip() for p in match.group(1).split(",")}
    assert named == _compose_host_ports(), named


def test_the_bundled_services_are_described_as_loopback_only_and_are():
    assert "published on 127.0.0.1 only" in _read(INSTALL_MD)
    specs = []
    for entries in re.findall(r"(?m)^\s*ports:\s*\[(.*)\]", _read(COMPOSE)):
        specs += re.findall(r'"([^"]+)"', entries)
    assert specs and all(s.startswith("127.0.0.1:") for s in specs), specs


# ---------------------------------------------------------------------------
# The legal gate: five items, and a pointer that resolves
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", (INSTALL_SH, INSTALL_PS1, INSTALL_MD),
                         ids=lambda p: p.name)
def test_the_legal_gate_is_five_items_and_points_at_a_real_heading(path: Path):
    text = _read(path)
    if path.suffix == ".md":
        shown = text
    else:
        # What a reader sees: the printed lines, and for install.sh the
        # header its --help prints. A comment recording the old wording is
        # not shown to anyone.
        shown = "\n".join(line for _, line in _printed_lines(path))
        if path.suffix == ".sh":
            shown += "\n" + _header_comment(text)
    flat = " ".join(re.sub(r"(?m)^\s*(#|>|Write-Host|printf)\s*", " ", shown).split())
    assert "Five legal decisions" in flat and "L1 to L5" in flat, path.name
    assert "Four legal decisions" not in flat and "LEGAL STATUS" not in flat
    assert "Five blocking items" in flat or "five-blocking-items" in shown
    if path.suffix != ".md":
        # release/README.md sits beside both installers and has no such
        # heading, so "README.md" alone sent a reader in release/ to the
        # wrong file. The banner and the help header both name the root
        # one (the header in capitals, hence the lower()).
        assert flat.lower().count("readme.md at the project root") >= 2, path.name


def test_the_readme_heading_the_banners_name_exists_with_five_rows():
    readme = _read(README)
    assert re.search(r"(?m)^#+ Five blocking items, none of them a software problem$",
                     readme)
    rows = re.findall(r"(?m)^\| \*\*(L\d)\*\* \|", readme)
    assert rows == ["L1", "L2", "L3", "L4", "L5"], rows


# ---------------------------------------------------------------------------
# What to do after the install
# ---------------------------------------------------------------------------

def _bootstrap():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import bootstrap
    return bootstrap


#: security.officer@, not officer@: officer@example.org is the account the
#: README's showcase seeder creates, so after the recipe the printed
#: command exited 1 with "already exists" (Alpha 6 pre-release check,
#: 2026-09-23).
_OFFICER_EMAIL = "security.officer@example.org"
_OFFICER_ARGS = ["create-user", "--email", _OFFICER_EMAIL,
                 "--name", "Officer Name", "--roles", "SECURITY_OFFICER"]


def _seeder_officer() -> str:
    """seed_readme_showcase.py's DEFAULT_OFFICER, read from the source: the
    seeder is not imported, because importing a script runs it."""
    tree = ast.parse(_read(SCRIPTS / "seed_readme_showcase.py"))
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "DEFAULT_OFFICER"
                        for t in node.targets)):
            return ast.literal_eval(node.value)
    raise AssertionError("seed_readme_showcase.py has no DEFAULT_OFFICER")


def test_the_closing_output_says_where_to_sign_in_and_what_comes_next():
    """The installer's first suggestion was `python scripts/bootstrap.py
    demo-case`: no `python` on a stock Ubuntu, the wrong seeder, and an
    API login for someone about to use the console."""
    sh = _read(INSTALL_SH)
    tail = sh[sh.find("step 'Starting the API'"):]
    assert 'detail "console:  http://127.0.0.1:$PORT/ui/"' in tail
    assert 'README.md, section "First run"' in tail
    assert ".venv/bin/python scripts/bootstrap.py demo-network --owner-email" in tail
    ps1 = _read(LAUNCH_PS1)
    assert ".venv\\Scripts\\python scripts\\bootstrap.py demo-network --owner-email" in ps1
    for text in (sh, ps1):
        assert "python scripts/bootstrap.py demo-case" not in text
    # And the command the two print is one bootstrap accepts.
    args = _bootstrap()._build_parser().parse_args(
        ["demo-network", "--owner-email", "you@example.org",
         "--code", "OP-SHOWCASE-26", "--classification", "CLEAR"])
    assert args.classification == "CLEAR"


def test_the_officer_advice_is_one_command_bootstrap_accepts_everywhere():
    """The installer's account holds CASE_OWNER and SYS_ADMIN, so a fresh
    install fails the blocking security_officer_present check. The advice
    is the same command in install.sh, launch.ps1 and INSTALL.md, with each
    platform's interpreter, and it parses."""
    tail = " ".join(_OFFICER_ARGS[:-1]) + " SECURITY_OFFICER"
    tail = tail.replace("Officer Name", '"Officer Name"')
    assert f".venv/bin/python scripts/bootstrap.py {tail}" in _read(INSTALL_SH)
    assert f".venv\\Scripts\\python scripts\\bootstrap.py {tail}" in _read(LAUNCH_PS1)
    install_md = " ".join(_read(INSTALL_MD).replace("\\\n", " ").split())
    assert f".venv/bin/python scripts/bootstrap.py {tail}" in install_md
    bootstrap = _bootstrap()
    args = bootstrap._build_parser().parse_args(_OFFICER_ARGS)
    assert args.func is bootstrap.cmd_create_user
    assert bootstrap._parse_roles(args.roles) == ["SECURITY_OFFICER"]
    # The default really does leave the role out, which is why the advice
    # is printed at all. If that changes, so should the advice.
    assert "SECURITY_OFFICER" not in bootstrap._parse_roles(bootstrap.DEFAULT_ROLES)


def test_the_example_officer_is_not_the_showcase_seeders_officer():
    """The printed officer command used the seeder's own address, so after
    the README recipe it failed with "already exists", and run first it
    would have made the seeder adopt the real officer's account. No
    installer, launcher or INSTALL.md command gives the seeder's address
    as the one to create. (Prose may still name the seeder's account.)"""
    seeded = _seeder_officer()
    assert seeded != _OFFICER_EMAIL, seeded
    alone = re.compile(rf"--email\s+{re.escape(seeded)}(?![\w.+-])")
    for path in (*SHELL_SCRIPTS, INSTALL_MD):
        hits = [line.strip() for _, line in _printed_lines(path)
                if alone.search(line)]
        assert not hits, (path.name, hits)


def test_install_md_names_the_register_checks_as_the_register_has_them():
    from noctornal_api import readiness
    text = " ".join(_read(INSTALL_MD).split())
    for name in ("security_officer_present", "preservation_bucket_object_lock"):
        assert f"`{name}`" in text and name in readiness.CHECK_NAMES, name
    assert "security_officer_present" in readiness.BLOCKING_CHECKS
    words = {3: "three", 4: "four", 5: "five"}
    blocking = len(readiness.BLOCKING_CHECKS)
    assert f"one of its {words[blocking]} blocking checks" in text
    others = sorted(set(readiness.BLOCKING_CHECKS) - {"security_officer_present"})
    listed = re.search(r"The other \w+ blocking checks on a fresh install "
                       r"\(([^)]*)\)", text)
    assert listed, "the list of the other blocking checks moved"
    assert sorted(re.findall(r"`(\w+)`", listed.group(1))) == others


# ---------------------------------------------------------------------------
# The README and INSTALL.md, against the tree
# ---------------------------------------------------------------------------

def test_the_readme_l1_row_says_what_a_rejection_does_now(monkeypatch):
    """Migration 0063 preserves a rejected sample by default; the row
    counsel reads first said the bytes were destroyed."""
    from noctornal_api.samples import (
        DESTROY,
        DISPOSITION_ENV,
        PRESERVE,
        disposition_setting,
    )
    row = next(ln for ln in _read(README).split("\n") if ln.startswith("| **L1** |"))
    assert "destroys the bytes" not in row
    assert "preserved by default" in row and "`noctornal-preserved`" in row
    assert f"`{DISPOSITION_ENV}={DESTROY}`" in row
    # And "by default" is the code's default, not the installers' line.
    monkeypatch.delenv(DISPOSITION_ENV, raising=False)
    assert disposition_setting() == (PRESERVE, None)


def test_the_readme_asks_for_an_account_only_when_there_is_none():
    readme = _read(README)
    first_run = readme[readme.index("## First run"):readme.index("### Verifying the install")]
    create = first_run.index("scripts/bootstrap.py create-user")
    assert "**Only if you have no account yet**" in first_run[:create]
    assert "the one you gave the installer" in first_run


@pytest.mark.parametrize("path", (README, INSTALL_MD), ids=lambda p: p.name)
def test_no_document_says_the_installer_opens_the_console(path: Path):
    """It prints the URL; it never opens a browser."""
    text = " ".join(_read(path).split())
    assert "starts the API and opens the console" not in text
    assert "and opens the console." not in text


def test_install_md_quotes_no_suite_total():
    """It said 1252 passed and roughly 700 skips on a tree that ran 1995
    and 1533. The collected total per release lives in the changelog."""
    text = _read(INSTALL_MD)
    stale = re.findall(r"\b\d+ (?:passed|skipped|skips|test files)\b", text)
    assert not stale, stale


#: One representative gate per leg INSTALL.md names as setting-gated.
_SETTING_GATES = {
    "test_cases_pg.py": "DATABASE_URL",
    "test_ratelimit_redis.py": "REDIS_URL",
    "test_curation_pg.py": "MINIO_ENDPOINT",
}


def test_install_md_says_a_loaded_setting_with_the_stack_down_errors():
    """The skip table said the database tests skip when "the containers
    are not up". They do not: they are gated on the setting alone, and the
    recipe loads DATABASE_URL from .env.local, so with Postgres down they
    error. The table now names settings only and says so (Alpha 6
    pre-release check, 2026-09-23)."""
    text = " ".join(_read(INSTALL_MD).split())
    assert "or the containers are not up" not in text
    assert "The table is about settings, not services." in text
    assert "with `.env.local` loaded and the containers down they **fail or error** rather than skip" in text
    readme = " ".join(_read(README).split())
    assert "With the containers up, expect **no failures**" in readme
    # And that is how the gates are written: on the variable, not on
    # whether the service answers. If one becomes a reachability probe,
    # the sentence above has become false for that leg.
    tests = ROOT / "apps" / "api" / "tests"
    for name, var in _SETTING_GATES.items():
        src = _read(tests / name)
        assert f'os.environ.get("{var}", "")' in src, name
        assert re.search(r"skipif\(\s*not \w+", src), name


_PREREQ_ROWS = ("Python", "Docker", "Memory", "Disk", "OS")


def _prerequisites(text: str) -> dict[str, str]:
    rows = {}
    for line in text.split("\n"):
        match = re.match(r"\| \*\*(\w+)\*\* \|(.*)$", line)
        if match and match.group(1) in _PREREQ_ROWS:
            rows.setdefault(match.group(1), match.group(2).strip())
    return rows


def test_one_prerequisites_table_in_both_documents():
    """INSTALL.md said any Docker, 4 GB and 2 GB; the README said Docker
    Desktop, 8 GB and 5 GB. Neither named python3.12-venv."""
    readme, install = _prerequisites(_read(README)), _prerequisites(_read(INSTALL_MD))
    assert set(readme) == set(install) == set(_PREREQ_ROWS), (readme, install)
    assert readme == install, {k: (readme[k], install[k])
                               for k in readme if readme[k] != install[k]}
    assert "python3.12-venv" in readme["Python"]
    assert "Docker Engine" in readme["Docker"] and "Docker Desktop" in readme["Docker"]


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped,
    spaces to hyphens."""
    text = re.sub(r"[`*]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(text: str) -> set[str]:
    return {_slug(m) for m in re.findall(r"(?m)^#{1,6} (.+)$", text)}


def test_links_between_the_readme_and_install_md_land_on_headings():
    """A link whose file exists is checked by test_doc_invariants; this
    checks the part after the `#`, for the two documents a new user reads
    first."""
    docs = {README: _read(README), INSTALL_MD: _read(INSTALL_MD)}
    broken = []
    for doc, text in docs.items():
        for target, anchor in re.findall(r"\]\(([^)\s#]*)#([^)\s]+)\)", text):
            dest = (doc.parent / target).resolve() if target else doc
            if dest not in docs:
                continue
            if anchor not in _anchors(docs[dest]):
                broken.append(f"{doc.name} -> {target or doc.name}#{anchor}")
    assert not broken, broken


# ---------------------------------------------------------------------------
# Alembic in a second terminal
# ---------------------------------------------------------------------------

def test_alembic_without_a_database_url_refuses_in_one_line():
    """It ended in a traceback, `RuntimeError: DATABASE_URL is not set`,
    followed by an em dash. It now says what to do and names .env.local,
    without loading it: migrations refuse to guess a target."""
    env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "current"], cwd=ROOT, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
    message = proc.stderr.strip()
    assert "Traceback" not in message, message
    # One line says it all. Anything else a newer Alembic prints on stderr
    # (a deprecation note, say) is not this refusal and is not held here.
    refusal = [ln for ln in message.splitlines() if "DATABASE_URL" in ln]
    assert len(refusal) == 1, message
    assert ".env.local" in refusal[0], refusal[0]
    # INSTALL.md's troubleshooting entry quotes it; the quote must be real.
    quoted = "DATABASE_URL is not set or is empty"
    assert quoted in refusal[0] and f'"{quoted}"' in _read(INSTALL_MD)
    assert not any(d in refusal[0] for d in DASHES), refusal[0]
