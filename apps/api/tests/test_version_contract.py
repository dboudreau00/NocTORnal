"""The version is declared in ONE place, and everything that reports it agrees.

## What was wrong before 2026-09-09

`apps/api/pyproject.toml` said `version = "0.1.0"`. `noctornal_api.__version__`
said `"0.4.0"`, and that is what FastAPI put in the OpenAPI document. Two
literals, two files, no test reading both, so they disagreed for three
releases and a reviewer reading the packaging metadata was told this was a
0.1 while the API told them 0.4. That is the codebase's own signature
defect -- a counter that claims something the code does not back -- in its
smallest possible form.

`__init__.py` now READS the version rather than declaring one, and these
tests hold every reporter of it to the one declaration.

Pure -- no database. Reads pyproject.toml, the package source, and the
app factory.
"""
from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = API_ROOT / "pyproject.toml"
PACKAGE_INIT = API_ROOT / "src" / "noctornal_api" / "__init__.py"


def _pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_the_package_version_is_the_pyproject_version():
    """The contract, read from both sides. Fails on the tree as it stood
    before 2026-09-09 (0.1.0 in pyproject, 0.4.0 in the package)."""
    import noctornal_api

    assert noctornal_api.__version__ == _pyproject_version(), (
        f"noctornal_api.__version__ is {noctornal_api.__version__!r} but "
        f"pyproject.toml declares {_pyproject_version()!r}. The version is "
        f"declared in pyproject.toml only; nothing else may carry a literal.")


def _version_literal_assignments(source: str) -> list[str]:
    """Every `__version__ = <constant>` in the module, as source text.

    Checked on the AST, not with a regex over the text: the module's own
    docstring quotes the literal it used to carry as a history lesson, and
    a text search reported the lesson as the defect (2026-09-09)."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if "__version__" in names and isinstance(node.value, ast.Constant):
            found.append(ast.unparse(node))
    return found


def test_the_package_source_carries_no_version_literal():
    """`__version__ = "x.y.z"` in the package is the second declaration
    this file exists to forbid. Reading pyproject at import time means the
    two cannot drift; a literal here means they can, silently."""
    literals = _version_literal_assignments(PACKAGE_INIT.read_text(encoding="utf-8"))
    assert not literals, (
        f"{PACKAGE_INIT.relative_to(API_ROOT).as_posix()} declares a version "
        f"literal ({literals}); it must read pyproject.toml instead")


def test_the_version_is_a_release_shape():
    """Whatever pyproject says must be something a release can be tagged
    with. A malformed value would still satisfy the equality above."""
    assert re.fullmatch(r"\d+\.\d+\.\d+", _pyproject_version()), _pyproject_version()


def test_the_app_reports_the_same_version():
    """The third reporter: `create_app()` passes `__version__` to FastAPI,
    which publishes it in the OpenAPI document when docs are enabled. If
    the wiring in `http/app.py` ever grew its own literal this is where it
    would show."""
    from noctornal_api.http.app import create_app

    assert create_app().version == _pyproject_version()
