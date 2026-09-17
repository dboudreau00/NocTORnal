"""Invariants that live in `scripts/` rather than in the API.

## Why this file exists

The suite had 1269 tests and not one of them looked at `scripts/`. So when
an installed package was finally used the way the documentation says to use
it, three seed scripts died on their first line of real work:

    RuntimeError: DATABASE_URL is not set

on a machine where DATABASE_URL was sitting in `.env.local` the whole time.
The R9 fix for exactly that failure had been made in `bootstrap.py` alone,
and a second, slightly different copy of it was later written into
`seed_deception_demo.py`. The remaining five scripts got neither.

Nothing caught it because nothing ran them, and nothing ran them because
they need a database, an object store and a seeded case. These checks are
STATIC instead — they parse the source and assert a property. That is
weaker than executing the script, and it is the check that would actually
have fired.

Pure: no database, no object store, no imports of the scripts themselves
(importing them executes module-level code, which is the thing under test).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"

#: Not a command, so not subject to the rules below: `_env.py` IS the
#: loader, and `check_source_hygiene.py` deliberately depends on nothing so
#: that it can run before anything is installed.
_NOT_COMMANDS = {"_env.py", "check_source_hygiene.py"}


def _scripts() -> list[Path]:
    found = sorted(p for p in SCRIPTS.glob("*.py")
                   if p.name not in _NOT_COMMANDS)
    assert found, f"no scripts found under {SCRIPTS} -- has the tree moved?"
    return found


def _db_scripts() -> list[Path]:
    """Only the scripts that touch the API package.

    Selected HERE, at collection, rather than by `pytest.skip` inside the
    test. CI fails the build on any skip at all -- the gate exists so that
    a dead Postgres leg cannot present as a green run with 100+ skips --
    and a permanent, deliberate skip would both break that job and teach
    everyone to read "N skipped" as normal. A parametrisation that never
    generates the uninteresting case needs no skip.
    """
    found = [p for p in _scripts()
             if any(m.startswith("noctornal_api")
                    for m in _imported_modules(_tree(p)))]
    assert found, "no script imports noctornal_api -- that cannot be right"
    return found


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_modules(tree: ast.Module) -> set[str]:
    """Every module named by an import, at ANY nesting depth.

    Depth matters: the seed scripts import `noctornal_api.db` inside
    `main()` rather than at module level, to keep a missing editable install
    from breaking `--help`. A module-level-only walk would see none of them.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


def _calls_named(tree: ast.Module, name: str) -> bool:
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id == name
               for n in ast.walk(tree))


@pytest.mark.parametrize("path", _db_scripts(), ids=lambda p: p.name)
def test_db_touching_scripts_load_env_local(path: Path) -> None:
    """A script that connects to the database must first read `.env.local`.

    `launch.ps1`, `launch.sh` and `open-ui.ps1` all self-load it, so a
    script that does not is the odd one out — and its failure is the
    confusing kind, naming a variable the operator can plainly see is set.
    """
    tree = _tree(path)
    assert "_env" in _imported_modules(tree), (
        f"{path.name} imports noctornal_api but not scripts/_env.py. Add:\n"
        f"    from _env import load_env_local  # noqa: E402\n"
        f"    load_env_local()\n"
        f"Without it the script fails with 'DATABASE_URL is not set' on any "
        f"normal install, because the value lives in .env.local and nothing "
        f"reads it.")
    assert _calls_named(tree, "load_env_local"), (
        f"{path.name} imports load_env_local but never calls it. The import "
        f"alone does nothing -- the environment stays empty.")


@pytest.mark.parametrize("path", _scripts(), ids=lambda p: p.name)
def test_no_second_copy_of_the_env_loader(path: Path) -> None:
    """One loader. R22 happened because there were two, disagreeing.

    `seed_deception_demo.py` grew a private `_load_env_local` that was
    subtly different from `bootstrap.py`'s -- no BOM handling. Two
    implementations of a rule is one implementation plus a latent bug.
    """
    defined = {n.name for n in ast.walk(_tree(path))
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "_load_env_local" not in defined and "load_env_local" not in defined, (
        f"{path.name} defines its own .env.local loader. There is exactly "
        f"one, in scripts/_env.py; import it instead.")


# ---------------------------------------------------------------------------
# The installers and launchers, 2026-08-07
# ---------------------------------------------------------------------------
#
# Same reasoning as the header: nothing executes these, because executing
# them installs a stack. Static checks are weaker than a run and are the
# checks that would have fired.

REPO = Path(__file__).resolve().parents[3]
INSTALLERS = (REPO / "release" / "install.ps1", REPO / "release" / "install.sh")
LAUNCHERS = (REPO / "scripts" / "launch.ps1", REPO / "scripts" / "launch.sh")


@pytest.mark.parametrize("path", INSTALLERS, ids=lambda p: p.name)
def test_a_generated_secret_is_checked_before_it_is_written(path: Path):
    """An unchecked subprocess produces an EMPTY secret in `.env.local`.

    Both installers took the output of `python -c "...urandom(32)..."` on
    trust. A broken venv, a missing DLL, an interpreter that dies on
    import: the variable is empty, the file is written with
    `NOCTORNAL_TOTP_KEK=`, and the installer announces "fresh random keys".

    The failure then LATCHES. Every later run takes the "already exists -
    left untouched" branch, so a recipient whose first run half-failed is
    permanently installed with an empty key and is told twice that it
    worked. Refusing BEFORE the write leaves no file, so re-running fixes
    it.

    In PowerShell this is the more dangerous of the two: `& cmd` does not
    stop the script on failure at all, where `set -euo pipefail` catches
    the non-zero exit in sh.
    """
    src = path.read_text(encoding="utf-8")
    assert "32" in src and ("not 32" in src or "-ne 32" in src), (
        f"{path.name} does not check that the generated TOTP key is "
        f"exactly 32 bytes -- envelope.py refuses anything else, but not "
        f"until run time, in a different program")
    # And it must refuse rather than warn: the write is the latch.
    assert "stop_with" in src or "Stop-With" in src


@pytest.mark.parametrize("path", LAUNCHERS, ids=lambda p: p.name)
def test_a_set_but_empty_variable_is_not_treated_as_unset(path: Path):
    """`SMTP_ALLOW_PLAINTEXT=` is a deliberate act, not an absence.

    Both launchers loaded `.env.local` over any variable that was empty,
    so an operator who blanked one to turn something OFF had the file's
    value put straight back on the next launch. `db.py` and
    `scripts/_env.py` both distinguish "set but empty" from "not set" on
    purpose -- `_env.py`'s docstring names this exact scenario -- and the
    launchers were undoing it two directories away.

    sh needs `${!name+x}` (defined) rather than `${!name:-}` (non-empty);
    PowerShell needs `$null -ne` rather than `IsNullOrWhiteSpace`, because
    GetEnvironmentVariable returns "" for a defined-empty variable and
    $null only for a missing one.
    """
    src = path.read_text(encoding="utf-8")
    # BOTH implementations, in both files. Each launcher applies this rule
    # twice -- once loading `.env.local`, once applying the development
    # defaults -- and when this test was first written the two disagreed
    # inside the same file. That is the cheapest lens in the roadmap:
    # diff two implementations of one rule against each other.
    if path.suffix == ".sh":
        assert src.count("${!name+x}") >= 2, (
            "launch.sh still tests a variable with `:-` somewhere, so a "
            "deliberately emptied variable is overwritten -- by "
            ".env.local, or by the development defaults, or both")
    else:
        assert "$null -ne $current" in src, (
            "launch.ps1's .env.local loader uses IsNullOrWhiteSpace, which "
            "cannot tell a defined-empty variable from a missing one")
        assert "$null -eq $current" in src, (
            "launch.ps1's defaults loop has the same gap: a blanked "
            "DATABASE_URL is silently replaced with the dev-stack DSN")
        assert "IsNullOrWhiteSpace($current)" not in src
    # Whichever it is, the empty case has to SAY something -- silently
    # honouring it is how nobody noticed the old behaviour either.
    assert "EMPTY" in src


# ---------------------------------------------------------------------------
# The clean-VM install run, 2026-09-17 (release/CLEAN-VM-INSTALL.md)
# ---------------------------------------------------------------------------
#
# Three defects stopped a new user on stock Ubuntu 24.04. None of them was
# reachable from this suite before, and none is reachable now by running
# anything: these are the static checks that would have fired.

SH_INSTALLER = REPO / "release" / "install.sh"


def test_the_venv_guard_asks_for_ensurepip_not_just_venv():
    """R25. `import venv` succeeds on a machine that cannot build one.

    `venv/` ships in python3-minimal; python3.12-venv carries `ensurepip`
    and the pip wheel it installs. So the guard, which asked only for
    `venv`, passed on a stock Ubuntu 24.04 and the install died two steps
    later inside `python -m venv`, printing Python's message about
    `apt install python3.12-venv` rather than one of this script's own
    "Cannot continue / What to do" blocks. Measured on a clean VM:
    `import venv` exit 0, `import ensurepip` exit 1.
    """
    src = SH_INSTALLER.read_text(encoding="utf-8")
    assert "import ensurepip" in src, (
        "install.sh checks `import venv`, which is true on every Debian "
        "and Ubuntu box whether or not a venv can actually be built. "
        "ensurepip is the one that decides")
    # And it must name the VERSIONED package: `apt install python3-venv`
    # on a host whose default python3 is not the interpreter the script
    # found installs the wrong one and changes nothing.
    assert "-venv" in src and "basename" in src, (
        "the message should name python3.12-venv, derived from the "
        "interpreter actually selected, not a bare python3-venv")


def test_a_half_built_venv_is_not_mistaken_for_a_good_one():
    """R26. A failed `venv` leaves bin/python and no pip.

    The "already built" test was `-x "$VENV_PY"` alone, which that
    wreckage satisfies. So the second run reported '.venv already exists',
    went on to install dependencies, and died with 'No module named pip':
    a message FURTHER from the cause than the first run's, and one that
    never mentioned the real fix again however many times it was re-run.
    Installing the package the first run named did not help. Only
    `rm -rf .venv` did, and nothing said so.
    """
    src = SH_INSTALLER.read_text(encoding="utf-8")
    assert '-x "$VENV/bin/pip"' in src, (
        "install.sh decides the environment is already built without "
        "checking for pip, so it cannot tell a working venv from the "
        "remains of a failed one")
    # A failure must not leave the wreckage behind for the next run.
    assert src.count('rm -rf "$VENV"') >= 2, (
        "a failed `python -m venv` must remove its partial directory, or "
        "the next run takes the already-exists path over it")


def test_the_readiness_probe_does_not_eat_the_installers_stdin():
    """R27. `docker compose exec` forwards stdin even with -T.

    -T disables the TTY, not the attach. Sixty iterations of the Postgres
    readiness loop therefore drained whatever the installer was given, and
    the account prompt below read EOF. Every non-interactive install hit
    it: piped input, cron, CI, cloud-init, Ansible, ssh without a TTY. A
    person at a keyboard never did, because a pty does not reach EOF,
    which is why it stood.
    """
    src = SH_INSTALLER.read_text(encoding="utf-8")
    probe = [ln for ln in src.splitlines() if "pg_isready" in ln]
    assert probe, "the Postgres readiness probe moved; this test is blind"
    assert any("/dev/null" in ln for ln in probe), (
        "`docker compose exec -T postgres pg_isready` runs without "
        "redirecting stdin, so it eats the answers meant for the account "
        "prompt and the install ends mid-sentence with no message")


def test_the_account_prompt_survives_end_of_input():
    """R27, second half. `read` returns non-zero at EOF and `set -e` acts
    on it BEFORE the emptiness test, so the branch written to handle "they
    gave nothing" was unreachable. The script just stopped, having printed
    `Email: ` and nothing after it, with exit 1 and no error.
    """
    src = SH_INSTALLER.read_text(encoding="utf-8")
    assert "set -e" in src, "if this is no longer set -e, re-read this test"
    reads = [ln for ln in src.splitlines() if ln.strip().startswith("read -r ADMIN")]
    assert len(reads) == 2, f"expected two prompts, found {len(reads)}"
    for line in reads:
        assert "|| true" in line, (
            f"unguarded `read` under set -e: {line.strip()!r}. At EOF this "
            f"ends the script instead of reaching the 'Skipped: both an "
            f"email and a display name are needed' branch below it")


@pytest.mark.parametrize("path", INSTALLERS, ids=lambda p: p.name)
def test_the_generated_env_declares_the_upload_caps(path: Path):
    """R28. Production refuses to boot without an evidence cap.

    `config.verify_environment` stops a production boot while
    NOCTORNAL_MAX_EVIDENCE_BYTES is unset, on purpose: a cap nobody chose
    is a cap nobody can be held to. The installers wrote every other
    setting and not that one, so the obvious act of promoting the
    generated `.env.local` to a real deployment met a boot refusal with no
    hint the line had ever been available. On the dev stack it showed up
    as `evidence_size_cap_declared` warning on a brand-new install.
    """
    src = path.read_text(encoding="utf-8")
    for key in ("NOCTORNAL_MAX_EVIDENCE_BYTES",
                "NOCTORNAL_MAX_SAMPLE_BYTES",
                "INGEST_BUCKET"):
        assert key in src, (
            f"{path.name} generates .env.local without {key}, so a fresh "
            f"install is born with a readiness warning it could have "
            f"avoided, and the file cannot be promoted as written")
