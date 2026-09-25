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

Since 2026-09-24 it also holds the two
optional extras, telegram and yara: that they are the only extras beside
dev, that every installer offers them by name and the image only by a
closed list, that CI installs them on one leg and runs the tests written
for their absence on another, that the launchers probe the new hard
dependencies, that every printed install hint carries the pins, and that
NOTICE.md names every new distribution with its licence.

Pure: reads files and installed metadata, installs nothing.
"""
from __future__ import annotations

import ast
import importlib.metadata as md
import importlib.util
import os
import re
import shutil
import subprocess
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

#: The extras are walked too, so their pins are held to the environment and
#: never reported stale (2026-09-24).
_ROOTS = (("noctornal-api", {"dev", "telegram", "yara"}), ("noctornal-ontology", {"dev"}))

#: What each optional extra installs at its root: the distributions that
#: must be present wherever the extras are required (CI's first leg).
_EXTRA_ROOTS = {"telegram": ("telethon", "python-socks"), "yara": ("yara-x",)}
_EXTRAS_REMEDY = ('pip install -c constraints.txt -e packages/ontology '
                  '-e "apps/api[dev,telegram,yara]"')

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


def _installed(name: str) -> bool:
    try:
        md.distribution(name)
    except md.PackageNotFoundError:
        return False
    return True


def _missing_extras() -> list[str]:
    return sorted(dist for dists in _EXTRA_ROOTS.values() for dist in dists
                  if not _installed(dist))


def _require_installed(*, closure: bool = False):
    """The two workspace packages always. The extras' distributions only
    where they must be present: in CI, whose first leg installs both
    extras, and, for a check that walks what they require (`closure`),
    wherever this suite runs, because the pins of pyaes, rsa and pyasn1
    are only reachable through an installed telethon. yara-x has no wheel
    for macOS 13, so a workstation there cannot install the yara extra and
    is not failed for it (2026-09-24)."""
    for name, _extras in _ROOTS:
        if not _installed(name):  # pragma: no cover - a bare checkout
            pytest.fail(f"{name} is not installed; install with "
                        f"`{_EXTRAS_REMEDY}` before running the suite")
    missing = _missing_extras()
    if not missing:
        return
    if os.environ.get("CI"):
        pytest.fail(f"the optional extras are not installed ({', '.join(missing)}); "
                    f"CI installs them with `{_EXTRAS_REMEDY}`")
    if closure:
        pytest.skip(f"{', '.join(missing)} not installed, so what the extras require "
                    f"cannot be walked here; install with `{_EXTRAS_REMEDY}` (on "
                    f"macOS 13, where yara-x has no wheel, use `[dev,telegram]`)")


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
    _require_installed(closure=True)
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


def test_the_installers_count_their_three_installs():
    """Three installs each (the packages, the best-effort dev extra, and
    the extras asked for by name): a fourth added without the flag is
    caught by the parametrised test above only if the scan sees it, so the
    count is pinned too."""
    for rel in ("release/install.sh", "release/install.ps1"):
        assert len(_pip_installs((ROOT / rel).read_text(encoding="utf-8"))) == 3, rel


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


# ---------------------------------------------------------------------------
# New hard dependencies and two optional extras (2026-09-24)
# ---------------------------------------------------------------------------

def _pyproject() -> dict:
    return tomllib.loads((ROOT / "apps/api/pyproject.toml").read_text(encoding="utf-8"))["project"]


def _requirements(specs) -> dict[str, Requirement]:
    return {canonicalize_name(Requirement(s).name): Requirement(s) for s in specs}


def test_the_extras_are_exactly_dev_telegram_and_yara():
    """No "socks" extra: python-socks's only run-time user is Telethon."""
    assert set(_pyproject()["optional-dependencies"]) == {"dev", "telegram", "yara"}


def test_the_hard_dependencies_name_every_new_pin():
    project = _pyproject()
    hard = _requirements(project["dependencies"])
    for name in ("numpy", "selectolax", "pefile", "urllib3", "certifi", "idna"):
        assert name in hard, f"{name} is imported by the API and not declared"
    for name in ("telethon", "python-socks", "yara-x"):
        assert name not in hard, f"{name} is an optional extra, not a hard dependency"
    # hpke, which the egress proxy seals its exits with, is 47.0 or newer.
    crypto = hard["cryptography"].specifier
    assert Version("47.0") in crypto and Version("46.9") not in crypto
    # 0.5 may move the lexbor API the forum parsers are written against.
    assert Version("0.4.12") in hard["selectolax"].specifier
    assert Version("0.5.0") not in hard["selectolax"].specifier
    extras = {name: _requirements(specs)
              for name, specs in project["optional-dependencies"].items()}
    assert set(extras["telegram"]) == {"telethon", "python-socks"}
    assert set(extras["yara"]) == {"yara-x"}
    assert "python-socks" in extras["dev"], "the wire-contract cases need it"
    pins = _pins()
    for name in ("numpy", "selectolax", "pefile", "telethon", "python-socks",
                 "pyaes", "rsa", "pyasn1", "yara-x"):
        assert name in pins, f"{name} is not pinned"


def test_the_constraints_header_names_its_two_exceptions():
    """The header promises wheels everywhere; the two distributions that do
    not meet that bar are named with why, in the file a release reads."""
    header = " ".join(line.lstrip("# ").strip() for line in
                      CONSTRAINTS.read_text(encoding="utf-8").splitlines()
                      if line.startswith("#"))
    assert re.search(r"pyaes \(the telegram extra\).{0,80}sdist", header), header
    assert re.search(r"yara-x \(the yara extra\).{0,80}macOS 14", header), header
    assert '"apps/api[dev,telegram,yara]"' in header


def _ci() -> str:
    return (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")


def _step(text: str, name: str) -> str:
    """One step of the workflow: from its `- name:` line to the next."""
    start = text.index(f"- name: {name}\n")
    following = text.find("\n      - ", start + 1)
    return text[start:following if following > 0 else len(text)]


def _matrix_legs(text: str) -> list[dict[str, str]]:
    block = text[text.index("matrix:"):text.index("    services:")]
    legs = []
    for chunk in block.split("- name: ")[1:]:
        leg = {"name": chunk.splitlines()[0].strip()}
        for line in chunk.splitlines()[1:]:
            key, sep, value = line.strip().partition(": ")
            if sep:
                leg[key] = value.strip()
        legs.append(leg)
    return legs


def test_ci_installs_every_extra_on_one_leg_and_none_on_the_other():
    text = _ci()
    legs = {leg["name"]: leg for leg in _matrix_legs(text)}
    assert set(legs) == {"Tests and migrations", "Tests without optional extras"}, legs
    full, bare = legs["Tests and migrations"], legs["Tests without optional extras"]
    assert set(full["extras"].split(",")) == set(_pyproject()["optional-dependencies"])
    assert bare["extras"] == "dev"
    install = _step(text, "Install")
    assert '-e "apps/api[${{ matrix.extras }}]"' in install
    assert "-c constraints.txt" in install


def test_ci_runs_the_extras_absent_job():
    """The first leg runs everything but the marked tests (they are written
    for the extras being absent), the second runs the marked tests alone,
    and the no-skip gate uses the same selection on each."""
    text = _ci()
    legs = {leg["name"]: leg for leg in _matrix_legs(text)}
    assert legs["Tests and migrations"]["select"] == "not extras_absent"
    assert legs["Tests without optional extras"]["select"] == "extras_absent"
    assert legs["Tests and migrations"]["full"] == "true"
    assert legs["Tests without optional extras"]["full"] == "false"
    assert 'name: ${{ matrix.name }}' in text
    # One run: the gate reads the Tests step's output rather than running
    # the suite again on the database the first run wrote to (2026-09-25).
    assert '-m "${{ matrix.select }}"' in _step(text, "Tests")
    assert "tee /tmp/tests.out" in _step(text, "Tests")
    gate = _step(text, "No tests were skipped")
    assert "pytest" not in gate and "/tmp/tests.out" in gate
    assert "passed, [0-9]+ skipped" in gate
    # Both legs get the database the marked readiness tests need.
    for step in ("Load extensions", "Create the least-privilege runtime role",
                 "Create the egress proxy role", "Migrate to head"):
        assert "matrix.full" not in _step(text, step), step
    markers = tomllib.loads((ROOT / "apps/api/pyproject.toml").read_text(
        encoding="utf-8"))["tool"]["pytest"]["ini_options"]
    assert any(m.startswith("extras_absent:") for m in markers["markers"])
    assert markers["addopts"] == "-m 'not extras_absent'"


def test_ci_creates_the_egress_role_before_migrating():
    text = _ci()
    runtime = text.index("- name: Create the least-privilege runtime role")
    egress = text.index("- name: Create the egress proxy role")
    migrate = text.index("- name: Migrate to head")
    assert runtime < egress < migrate
    step = _step(text, "Create the egress proxy role")
    assert ("if [ -f db/init/20-egress-role.sh ]; then sh db/init/20-egress-role.sh; fi"
            in step)
    # 10-app-role.sh's pattern: psql with no --host, so the step names the
    # server the way its sibling does.
    for name in ("PGHOST: localhost", "PGPASSWORD:", "POSTGRES_USER:", "POSTGRES_DB:"):
        assert name in step, name
    head = text[:text.index("jobs:")]
    assert "NOCTORNAL_EGRESS_DB_ROLE: noctornal_egress" in head
    assert "NOCTORNAL_EGRESS_DB_PASSWORD:" in head


def test_ci_creates_the_collected_raw_markup_bucket_without_a_lock():
    text = _ci()
    assert "COLLECT_RAW_BUCKET: noctornal-collect-raw" in text[:text.index("jobs:")]
    buckets = _step(text, "Create the object-store buckets")
    line = next(li for li in buckets.splitlines() if "noctornal-collect-raw" in li
                and "mc mb" in li)
    assert "--with-lock" not in line


def test_the_installers_offer_each_extra_by_name():
    sh = (ROOT / "release/install.sh").read_text(encoding="utf-8")
    header = "\n".join(line for line in sh.splitlines()[:30] if line.startswith("#"))
    for switch in ("--with-telegram", "--with-yara"):
        assert f"./release/install.sh {switch}" in header, switch
        assert f"    {switch}) " in sh, switch
    extras_install = [c for c in _pip_installs(sh) if "[$EXTRAS]" in c]
    assert len(extras_install) == 1 and '-c "$CONSTRAINTS"' in extras_install[0]
    assert "stop_with" in extras_install[0], "a requested extra fails loudly"
    ps1 = (ROOT / "release/install.ps1").read_text(encoding="utf-8")
    for switch in ("WithTelegram", "WithYara"):
        assert f"[switch] ${switch}" in ps1, switch
        assert f".PARAMETER {switch}" in ps1, switch
    # ONE string, or pip installs the package without the extras.
    assert "(Join-Path $RepoRoot 'apps\\api') + \"[$extrasText]\"" in ps1
    assert "-c $Constraints -e $extrasTarget" in ps1


def _docker_extras_guard(text: str) -> tuple[set[str], str]:
    joined = re.sub(r"\\\r?\n\s*", " ", text)
    run = next(line for line in joined.splitlines() if 'case "$NOCTORNAL_EXTRAS" in' in line)
    allowed = re.search(r'in\s+(\S+)\)\s*;;', run).group(1)
    return {a.strip('"') for a in allowed.split("|")}, run


def test_the_image_takes_extras_only_by_name():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'ARG NOCTORNAL_EXTRAS=""' in text
    allowed, run = _docker_extras_guard(text)
    assert allowed == {"", "telegram", "yara", "telegram,yara", "yara,telegram"}
    assert "*) echo" in run and "exit 1" in run
    assert run.index("esac") < run.index("pip install")
    assert '-e "apps/api${NOCTORNAL_EXTRAS:+[$NOCTORNAL_EXTRAS]}"' in run
    assert "ONE image, five commands" in text and "egress_proxy" in text
    sh = shutil.which("sh")
    if sh is None:
        return  # the static reading above holds the guard where no sh runs it
    guard = run[run.index("case "):run.index("esac") + len("esac")]
    for value, code in (("", 0), ("telegram", 0), ("telegram,yara", 0),
                        ("socks", 1), ("telegram;id", 1), ("dev", 1)):
        result = subprocess.run([sh, "-c", guard], env={**os.environ,
                                "NOCTORNAL_EXTRAS": value},
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == code, (value, result.stderr)


def _launcher_probe(rel: str) -> str:
    text = (ROOT / rel).read_text(encoding="utf-8")
    return next(line for line in text.splitlines()
                if "import uvicorn, alembic" in line and not line.lstrip().startswith("#"))


@pytest.mark.parametrize("rel", ["scripts/launch.sh", "scripts/launch.ps1"])
def test_the_launchers_probe_every_new_hard_dependency(rel):
    """A venv built before the roadmap build is told to reinstall at
    launch, not at the first CONCOR run or forum poll. The extras are not
    probed: their absence is a readiness gap, not a broken venv."""
    probe = _launcher_probe(rel)
    for module in ("numpy", "selectolax", "pefile"):
        assert re.search(rf"\b{module}\b", probe), (rel, module)
    for module in ("telethon", "yara_x", "python_socks"):
        assert module not in probe, (rel, module)


#: What "pip install" may install without the pins: nothing this repository
#: declares. A hint naming a distribution nothing declares cannot be held to
#: a pin (scripts/yara_db.py's yara-python, which the yara extra retires).
_WORKSPACE_TARGETS = ("packages/ontology", "packages\\ontology", "apps/api", "apps\\api",
                      "requirements.txt")


def _needs_pins(command: str, pins: dict[str, str]) -> bool:
    words = command.split("pip install", 1)[1].replace('"', " ").replace("'", " ").split()
    if any(w in ("-e", "-r", "--editable", "--requirement") for w in words):
        return True
    for word in words:
        if any(t in word for t in _WORKSPACE_TARGETS):
            return True
        name = re.split(r"[\[<>=!~;]", word, maxsplit=1)[0]
        if name and canonicalize_name(name) in pins:
            return True
    return False


def _pinned(command: str) -> bool:
    return any(flag in command for flag in ("-c constraints.txt", '-c "$CONSTRAINTS"',
                                            "-c $Constraints", "'-c', $Constraints"))


def _python_strings(path: Path) -> list[str]:
    """Every string a Python file could print: its literals and f-strings,
    docstrings excluded (they document, they are not printed)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant):
                docstrings.add(id(body[0].value))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            found.append("".join(v.value if isinstance(v, ast.Constant) else "{}"
                                 for v in node.values))
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in docstrings):
            found.append(node.value)
    return found


def _hint_sources() -> list[tuple[str, str]]:
    hints = []
    for base in (ROOT / "scripts", ROOT / "apps/api/src"):
        for path in sorted(base.rglob("*.py")):
            for text in _python_strings(path):
                if "pip install" in text:
                    hints.append((str(path.relative_to(ROOT)), text))
    for pattern in ("*.sh", "*.ps1"):
        for path in sorted((ROOT / "scripts").glob(pattern)):
            joined = re.sub(r"\\\r?\n\s*", " ", path.read_text(encoding="utf-8"))
            for line in joined.splitlines():
                if "pip install" in line and not line.lstrip().startswith("#"):
                    hints.append((str(path.relative_to(ROOT)), line.strip()))
    return hints


def test_every_printed_install_hint_uses_the_constraints_file():
    """The launchers and bootstrap are held by name above; this holds every
    hint a later change adds, in any script or in the API, without a new
    row: a printed `pip install` of the workspace packages, of
    db/requirements.txt or of anything constraints.txt pins carries the
    pins, or the developer who follows it word for word runs a stack
    nobody tested."""
    pins = _pins()
    hints = _hint_sources()
    assert any("bootstrap.py" in where for where, _ in hints), "this test is blind"
    unpinned = [f"{where}: {text.strip()}" for where, text in hints
                if _needs_pins(text, pins) and not _pinned(text)]
    assert not unpinned, "\n".join(unpinned)


def test_the_hint_scan_tells_a_pinned_hint_from_an_unpinned_one():
    pins = _pins()
    assert _needs_pins("pip install numpy", pins) and not _pinned("pip install numpy")
    assert _needs_pins("python -m pip install -e apps/api", pins)
    assert _pinned("python -m pip install -c constraints.txt -e apps/api")
    assert not _needs_pins("pip install yara-python for compile validation.", pins)


_NOTICE_LICENCES = {
    "numpy": "BSD-3-Clause", "OpenBLAS": "BSD-3-Clause",
    "libgfortran": "GPL-3.0-or-later", "libquadmath": "LGPL-2.1-or-later",
    "selectolax": "MIT", "lexbor": "Apache-2.0", "Modest": "LGPL-2.1",
    "pefile": "MIT", "python-socks": "Apache-2.0",
    "telethon": "MIT", "pyaes": "MIT", "rsa": "Apache-2.0", "pyasn1": "BSD-2-Clause",
    "yara-x": "BSD-3-Clause", "urllib3": "MIT", "certifi": "MPL-2.0",
}


def test_notice_names_every_new_dependency_and_its_licence():
    text = (ROOT / "NOTICE.md").read_text(encoding="utf-8")
    section = text[text.index("## Dependencies added for the 2026-09 roadmap build"):]
    for name, licence in _NOTICE_LICENCES.items():
        rows = [line for line in section.splitlines() if name in line]
        assert any(licence in row for row in rows), (name, licence)
    # lexbor's NOTICE, verbatim from the selectolax 0.4.12 sdist.
    assert "   Lexbor.\n\n   Copyright 2018-2020 Alexander Borisov\n" in text.replace("\r\n", "\n")
    assert 'Licensed under the Apache License, Version 2.0 (the "License");' in text
    # The old claim that everything else is permissive is corrected.
    assert "Everything else in the tree is permissive (MIT, BSD-3-Clause, Apache-2.0,\nPSF, ISC) and imposes only attribution. The two" not in text.replace("\r\n", "\n")
    assert "MPL-2.0" in text[:text.index("## Dependencies added")]


@pytest.mark.extras_absent
def test_the_extras_absent_leg_has_no_optional_extra():
    """Runs only on the CI leg that installs apps/api[dev] alone (the
    marker is deselected everywhere else): it proves that leg really is
    the configuration most deployments have, so the tests marked for
    it run against a missing Telethon and a missing yara-x, not against a
    stale cache."""
    for module in ("telethon", "yara_x"):
        assert importlib.util.find_spec(module) is None, module
    assert _installed("noctornal-api")
