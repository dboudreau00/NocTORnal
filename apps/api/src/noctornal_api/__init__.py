"""NocTORnal API service.

`__version__` is read, not declared: the one declaration is `[project] version` in
`apps/api/pyproject.toml`, resolved at import time. In a source checkout that file is read
directly, because an editable install's metadata reports the version from when `pip install -e`
last ran; the installed metadata is used only when there is no such file (a wheel). A version that
cannot be determined raises, never a guess.
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
