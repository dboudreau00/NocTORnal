"""The version is declared in ONE place, and everything that reports it agrees.

`apps/api/pyproject.toml` declares the version and `noctornal_api.__init__` READS it rather than
declaring another, so the packaging metadata, the package and the OpenAPI document cannot disagree.
These tests hold every reporter of it to the one declaration.

Pure: no database. Reads pyproject.toml, the package source, and the app factory.
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
    """The contract, read from both sides: the package version is the pyproject version."""
    import noctornal_api

    assert noctornal_api.__version__ == _pyproject_version(), (
        f"noctornal_api.__version__ is {noctornal_api.__version__!r} but "
        f"pyproject.toml declares {_pyproject_version()!r}. The version is "
        f"declared in pyproject.toml only; nothing else may carry a literal.")


def _version_literal_assignments(source: str) -> list[str]:
    """Every `__version__ = <constant>` in the module, as source text.

    Checked on the AST, not with a regex over the text, so a docstring that quotes a literal is not
    reported as the defect."""
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


PRODUCTION_COMPOSE = API_ROOT.parents[1] / "infra" / "production" / "compose.yml"


def test_the_production_image_is_tagged_with_the_version():
    """The fourth reporter: `infra/production/compose.yml` tags the image it builds.

    Equality with pyproject, not a particular version: a release preparation that bumps pyproject alone
    would go on tagging images with the old version, and this fails on a commit that moves one without
    the other. Read as text: the tag is one line, and parsing YAML for it would add a dependency this
    pure test does not otherwise need."""
    text = PRODUCTION_COMPOSE.read_text(encoding="utf-8")
    tags = re.findall(r"^\s*image:\s*noctornal-api:(\S+)\s*$", text, re.M)
    assert tags, "infra/production/compose.yml builds no noctornal-api image"
    assert set(tags) == {_pyproject_version()}, (
        f"infra/production/compose.yml tags noctornal-api as {sorted(set(tags))} "
        f"but pyproject.toml declares {_pyproject_version()!r}")
