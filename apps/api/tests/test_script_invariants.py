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
