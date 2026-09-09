"""NocTORnal API service.

`__version__` is READ, not declared. The one declaration is `[project]
version` in `apps/api/pyproject.toml`; this module resolves it at import
time and raises if it cannot, rather than carrying a literal that can
disagree with it.

## Why pyproject first and the installed metadata second

Until 2026-09-09 this file said `__version__ = "0.4.0"` while
`pyproject.toml` said `0.1.0`, and nothing read both, so the packaging
metadata and the OpenAPI document disagreed for three releases. The obvious
repair is `importlib.metadata.version("noctornal-api")` -- but that reports
the version recorded when `pip install -e` LAST RAN, not the one in the file
now. On this repository's own development venv it reported `0.1.0` on
2026-09-09 with pyproject already at `0.4.0`: metadata-first would have
reproduced the exact disagreement this change removes, in precisely the
environment where the version is being changed. So in a source checkout the
`pyproject.toml` beside the source is read directly, and the installed
metadata is used only when there is no such file (a wheel in site-packages),
where it was built from that same file and cannot differ from it.

There is no third fallback and no literal: a version that cannot be
determined is an error, not a guess.
"""
from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

_DISTRIBUTION = "noctornal-api"


def _read_version() -> str:
    # apps/api/src/noctornal_api/__init__.py -> apps/api/pyproject.toml
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if pyproject.is_file():
        with pyproject.open("rb") as fh:
            project = tomllib.load(fh).get("project", {})
        # Only trust a pyproject that is THIS distribution's. An unrelated
        # project that happens to sit two directories above an installed
        # copy must not supply our version.
        if project.get("name") == _DISTRIBUTION:
            version = project.get("version")
            if not isinstance(version, str) or not version:
                raise RuntimeError(f"{pyproject} declares no [project] version")
            return version
    try:
        return importlib.metadata.version(_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            f"noctornal_api: no pyproject.toml beside the source and no installed "
            f"metadata for {_DISTRIBUTION!r}; the version cannot be determined and "
            f"is deliberately not guessed"
        ) from exc


__version__ = _read_version()
