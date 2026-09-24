"""The Python stack and the Mailpit image are pinned, and everything that
installs them uses the pins (sec-pin-dependencies, 2026-09-23).

Until that date nothing was pinned. Every dependency in the pyproject files
is a floor, so a clean install resolved each one to whatever was newest on
the day: the clean VM of the Alpha 6 pre-release check ran starlette 1.7.0,
uvicorn 0.53.0, alembic 1.20.0, psycopg 3.3.6, SQLAlchemy 2.0.54 and
`axllent/mailpit:latest` (v1.31.2) while the suite had passed on older
releases of every one (release/CLEAN-VM-INSTALL.md, F17 and G9).

What this file holds, each half because the other can pass without it:

* constraints.txt is well formed: exact pins, one per distribution, no
  extras (pip refuses extras in a constraints file);
* every dependency the pyproject files and db/requirements.txt DECLARE is
  pinned, inside its declared range;
* the environment this suite is running in IS the pinned one: every
  distribution noctornal-api[dev] and noctornal-ontology[dev] pull in is
  pinned at the version installed, and no pin names a distribution nothing
  asks for. In CI that proves the `-c` took effect; on a workstation it
  proves the suite is passing on the stack the release ships;
* every place that installs the packages (both installers, CI and the
  Dockerfile) installs with `-c constraints.txt`;
* Mailpit is a release tag, the same one in the compose file and in CI.

Pure: reads files and installed metadata, installs nothing.
"""
from __future__ import annotations

import importlib.metadata as md
import re
import tomllib
from pathlib import Path

import pytest
from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[3]
CONSTRAINTS = ROOT / "constraints.txt"
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!-]+)$")


def _pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for number, raw in enumerate(CONSTRAINTS.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = _PIN.match(line)
        assert match, f"constraints.txt line {number} is not `name==version`: {raw!r}"
        name = canonicalize_name(match.group(1))
        assert name not in pins, f"constraints.txt pins {name} twice"
        pins[name] = match.group(2)
    return pins


def _declared() -> list[tuple[str, Requirement]]:
    """Every requirement a file in this repository declares, with where."""
    found = []
    for rel in ("apps/api/pyproject.toml", "packages/ontology/pyproject.toml"):
        project = tomllib.loads((ROOT / rel).read_text(encoding="utf-8"))["project"]
        for spec in project.get("dependencies", []):
            found.append((rel, Requirement(spec)))
        for extra, specs in project.get("optional-dependencies", {}).items():
            for spec in specs:
                found.append((f"{rel} [{extra}]", Requirement(spec)))
    for raw in (ROOT / "db" / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            found.append(("db/requirements.txt", Requirement(line)))
    return found


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------

def test_the_constraints_file_is_exact_pins_and_nothing_else():
    pins = _pins()
    assert len(pins) >= 40, f"only {len(pins)} pins; the file lost its body"
    for name, version in pins.items():
        Version(version)  # raises on anything that is not a version
        assert "[" not in name, name


def test_every_declared_dependency_is_pinned_inside_its_range():
    pins = _pins()
    problems = []
    for where, requirement in _declared():
        name = canonicalize_name(requirement.name)
        if name not in pins:
            problems.append(f"{where}: {requirement} is not pinned")
            continue
        if Version(pins[name]) not in requirement.specifier:
            problems.append(f"{where}: {requirement} excludes the pin {pins[name]}")
        for extra in requirement.extras:
            # psycopg[binary] installs psycopg-binary, which has to be pinned
            # too or the extra floats while its parent is held.
            if extra == "binary":
                assert canonicalize_name(f"{requirement.name}-binary") in pins, requirement
    assert not problems, "\n".join(problems)


# ---------------------------------------------------------------------------
# The environment this suite runs in
# ---------------------------------------------------------------------------

_ROOTS = (("noctornal-api", {"dev"}), ("noctornal-ontology", {"dev"}))

#: The marker environments the pins have to serve: the installers accept
#: CPython 3.12 or newer on Linux, Windows and macOS.
_PLATFORMS = [
    {"sys_platform": plat, "platform_system": system, "os_name": os_name,
     "platform_machine": machine, "python_version": py,
     "python_full_version": f"{py}.0", "implementation_name": "cpython",
     "platform_python_implementation": "CPython"}
    for plat, system, os_name, machine in (
        ("linux", "Linux", "posix", "x86_64"), ("win32", "Windows", "nt", "AMD64"),
        ("darwin", "Darwin", "posix", "arm64"))
    for py in ("3.12", "3.13", "3.14")
]


def _walk(environments):
    """`{name: installed version or None}` for everything the two packages
    pull in under any of `environments` (None: required somewhere else,
    not installed on this platform)."""
    seen: dict[str, str | None] = {}
    stack = [(name, extras) for name, extras in _ROOTS]
    done: set[tuple[str, frozenset]] = set()
    while stack:
        name, extras = stack.pop()
        key = (canonicalize_name(name), frozenset(extras))
        if key in done:
            continue
        done.add(key)
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            seen.setdefault(canonicalize_name(name), None)
            continue
        seen[canonicalize_name(name)] = dist.version
        for spec in dist.requires or []:
            requirement = Requirement(spec)
            marker: Marker | None = requirement.marker
            if marker is not None and not any(
                    marker.evaluate({**env, "extra": extra})
                    for env in environments for extra in (extras or {""})):
                continue
            stack.append((requirement.name, set(requirement.extras)))
    return seen


def _require_installed():
    for name, _extras in _ROOTS:
        try:
            md.distribution(name)
        except md.PackageNotFoundError:  # pragma: no cover - a bare checkout
            pytest.fail(f"{name} is not installed; install with "
                        f"`pip install -c constraints.txt -e packages/ontology "
                        f"-e \"apps/api[dev]\"` before running the suite")


def test_the_installed_stack_is_the_pinned_stack():
    """Every distribution the two packages pull in HERE is pinned, at the
    version installed. Run by CI after `pip install -c constraints.txt`,
    this is what proves the suite passed on the pins and not on whatever
    PyPI served; on a workstation, a venv that drifted from the pins is
    named, distribution by distribution."""
    _require_installed()
    import platform
    import sys
    here = {"sys_platform": sys.platform, "platform_system": platform.system(),
            "os_name": __import__("os").name, "platform_machine": platform.machine(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "python_full_version": platform.python_version(),
            "implementation_name": sys.implementation.name,
            "platform_python_implementation": platform.python_implementation()}
    pins = _pins()
    drift = []
    for name, version in sorted(_walk([here]).items()):
        if name in ("noctornal-api", "noctornal-ontology"):
            continue
        if name not in pins:
            drift.append(f"{name} {version} is installed and not pinned")
        elif version is not None and version != pins[name]:
            drift.append(f"{name} is {version} here and pinned at {pins[name]}")
    assert not drift, ("the environment is not the pinned stack; reinstall with "
                       "-c constraints.txt, or move the pins and re-run the "
                       "suite:\n  " + "\n  ".join(drift))


def test_no_pin_names_a_distribution_nothing_asks_for():
    """A dependency dropped from a pyproject file leaves its pin behind,
    and a stale pin is the file claiming a stack it no longer describes.
    Walked across every platform the installers accept, so a Windows-only
    dependency (colorama) is not called stale on Linux."""
    _require_installed()
    reachable = set(_walk(_PLATFORMS))
    stale = sorted(set(_pins()) - reachable)
    assert not stale, f"pinned and required by nothing: {stale}"


# ---------------------------------------------------------------------------
# Everything that installs, installs with the pins
# ---------------------------------------------------------------------------

def _pip_installs(text: str) -> list[str]:
    """Each `pip install` command in `text`, continuation lines joined, the
    upgrade of pip itself left out (it is not a dependency of anything)."""
    joined = re.sub(r"\\\r?\n\s*", " ", text)
    commands = []
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r"pip['\"]?\s*,?\s*['\"]?install\b", stripped) and "--upgrade pip" not in stripped:
            commands.append(stripped)
    return commands


@pytest.mark.parametrize("rel, flag", [
    ("release/install.sh", '-c "$CONSTRAINTS"'),
    ("release/install.ps1", "-c $Constraints"),
    (".github/workflows/ci.yml", "-c constraints.txt"),
    ("Dockerfile", "-c constraints.txt"),
    # c3 (2026-09-24): the remedies these three PRINT are installs too.
    # start.cmd runs launch.ps1 on a fresh clone before anything else, so
    # its "no .venv" hint is the first install many developers run, and it
    # left the pins off while the four files above kept them. The scan
    # already reads quoted hint strings, so listing them is the whole fix.
    ("scripts/launch.ps1", "-c constraints.txt"),
    ("scripts/launch.sh", "-c constraints.txt"),
    ("scripts/bootstrap.py", "-c constraints.txt"),
])
def test_every_install_uses_the_constraints_file(rel, flag):
    text = (ROOT / rel).read_text(encoding="utf-8")
    commands = _pip_installs(text)
    assert commands, f"{rel}: no pip install found; this test is blind"
    ps_flag = "'-c', $Constraints"
    unpinned = [c for c in commands if flag not in c and ps_flag not in c]
    assert not unpinned, f"{rel} installs without the pins: {unpinned}"


@pytest.mark.parametrize("rel, name", [
    ("release/install.sh", 'CONSTRAINTS="$REPO_ROOT/constraints.txt"'),
    ("release/install.ps1", "$Constraints = Join-Path $RepoRoot 'constraints.txt'"),
])
def test_the_installers_find_the_file_at_the_repository_root(rel, name):
    """And say so by name when it is missing, rather than letting pip's
    error arrive as "dependency installation failed"."""
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert name in text, rel
    assert "constraints.txt is missing" in text, rel


def test_the_installers_count_both_their_installs():
    """Two installs each (the packages, then the dev extra): a third added
    without the flag is caught by the parametrised test above only if the
    scan sees it, so the count is pinned too."""
    for rel in ("release/install.sh", "release/install.ps1"):
        assert len(_pip_installs((ROOT / rel).read_text(encoding="utf-8"))) == 2, rel


def test_the_constraints_file_reaches_the_image():
    """The Dockerfile copies the whole tree through .dockerignore; a rule
    that dropped the file would fail the build at `pip install -c`."""
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    rules = [r.strip() for r in ignored if r.strip() and not r.startswith("#")]
    for rule in rules:
        assert not re.fullmatch(rule.replace(".", r"\.").replace("*", ".*"),
                                "constraints.txt"), rule


# ---------------------------------------------------------------------------
# Mailpit
# ---------------------------------------------------------------------------

_MAILPIT = re.compile(r"axllent/mailpit:(\S+)")


def test_mailpit_is_a_release_tag_and_the_same_one_everywhere():
    tags = {}
    for rel in ("infra/docker-compose.yml", ".github/workflows/ci.yml"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        used = {m for line in text.splitlines() if not line.lstrip().startswith("#")
                for m in _MAILPIT.findall(line)}
        assert len(used) == 1, f"{rel} runs Mailpit as {sorted(used)}"
        tags[rel] = used.pop()
    assert len(set(tags.values())) == 1, tags
    tag = next(iter(tags.values()))
    assert re.fullmatch(r"v\d+\.\d+\.\d+", tag), (
        f"{tag!r} is not a release tag; `latest`, `v1` and `edge` all move")


@pytest.mark.parametrize("rel", ["infra/docker-compose.yml", ".github/workflows/ci.yml"])
def test_no_image_runs_at_latest(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    live = [line.strip() for line in text.splitlines()
            if not line.lstrip().startswith("#") and ":latest" in line]
    assert not live, f"{rel}: {live}"
