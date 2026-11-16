"""docs/17 "YARA in the worker": the production image carries yara-x by default, from a hash-pinned file.

The analysis worker runs the application image, so the image a plain `docker build` makes is the one that
must scan. What this file holds: the Dockerfile's default extra is yara and only an explicit empty value
leaves it out; the image installs yara-x from requirements-yara.txt with its hashes required, before the
editable install that would otherwise fetch it unhashed; the file pins the version constraints.txt pins,
with one hash per Linux architecture; the file reaches the build context; and CI downloads both wheels
with the hashes required.

Pure: reads files, and runs the Dockerfile's shell fragment with a POSIX shell where one is installed.
Nothing here needs Docker.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from packaging.version import Version
from test_dependency_pins import _ci, _hashed_requirements, _job, _pins, _step
from test_image_context_and_production_stack import Dockerignore

ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = ROOT / "Dockerfile"
YARA_PIN = ROOT / "requirements-yara.txt"
_WHEEL = "yara_x-<version>-cp38-abi3-manylinux_2_28_{}.whl"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _install_run() -> str:
    """The Dockerfile's RUN that installs the packages, continuation lines joined."""
    joined = re.sub(r"\\\n\s*", " ", _text(DOCKERFILE))
    return next(line for line in joined.splitlines()
                if line.startswith("RUN ") and 'case "$NOCTORNAL_EXTRAS" in' in line)


def test_the_dockerfile_defaults_to_the_yara_extra():
    """A plain build makes an image that scans; telegram stays opt-in."""
    defaults = re.findall(r'(?m)^ARG NOCTORNAL_EXTRAS=(.*)$', _text(DOCKERFILE))
    assert defaults == ['"yara"'], defaults


def test_the_production_image_installs_yara_from_the_hash_pinned_file_before_the_editable_install():
    run = _install_run()
    guard = run.index("esac")
    hashed = run.index("-r requirements-yara.txt")
    editable = run.index('-e "apps/api${NOCTORNAL_EXTRAS:+[$NOCTORNAL_EXTRAS]}"')
    assert guard < hashed < editable, "the closed list first, the hashed wheel before the editable install"
    command = run[run.rindex("pip install", 0, hashed):hashed]
    for flag in ("--require-hashes", "--only-binary=:all:", "--no-deps", "-c constraints.txt",
                 "--no-cache-dir"):
        assert flag in command, flag
    assert 'case ",$NOCTORNAL_EXTRAS," in' in run and "*,yara,*)" in run


def _hashed_branch() -> str:
    run = _install_run()
    start = run.index('case ",$NOCTORNAL_EXTRAS," in')
    return run[start:run.index("esac", start) + len("esac")]


def test_the_hashed_install_runs_exactly_when_the_extras_name_yara():
    """The second `case` reads the list the closed `case` before it has already admitted."""
    sh = shutil.which("sh")
    if sh is None:
        return  # the static reading above holds the order where no sh runs it
    branch = "pip() { echo HASHED; }; " + _hashed_branch()
    for value, hashed in (("yara", True), ("telegram,yara", True), ("yara,telegram", True),
                          ("telegram", False), ("", False)):
        result = subprocess.run([sh, "-c", branch], env={**os.environ, "NOCTORNAL_EXTRAS": value},
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, (value, result.stderr)
        assert ("HASHED" in result.stdout) is hashed, value


def test_requirements_yara_pins_the_version_constraints_pins():
    pins = _hashed_requirements(YARA_PIN)
    assert set(pins) == {"yara-x"}, pins
    version, _hashes = pins["yara-x"]
    Version(version)
    assert _pins()["yara-x"] == version, "move requirements-yara.txt and constraints.txt together"


def test_requirements_yara_hashes_are_64_hex_and_cover_both_linux_architectures():
    """One wheel hash per architecture a production host builds on, and the header names the two
    files they are the hashes of, so the next person to move the pin takes the same two."""
    _version, hashes = _hashed_requirements(YARA_PIN)["yara-x"]
    assert len(hashes) == 2 and len(set(hashes)) == 2, hashes
    header = _text(YARA_PIN)
    for arch in ("x86_64", "aarch64"):
        assert _WHEEL.format(arch) in header, arch


def test_requirements_yara_reaches_the_image():
    """The Dockerfile copies the tree through .dockerignore; a rule that dropped the file would fail
    every default build at its `-r`."""
    ignore = Dockerignore(_text(ROOT / ".dockerignore"))
    assert not ignore.excluded("requirements-yara.txt")


def test_ci_downloads_both_yara_wheels_with_the_hashes_required():
    """A hash PyPI does not serve fails CI's Pinned images resolve job, by name, before a production
    build meets it."""
    step = _step(_job(_ci(), "pinned-images"), "Every hash-pinned requirement resolves on PyPI")
    assert "set -euo pipefail" in step
    assert "for platform in manylinux_2_28_x86_64 manylinux_2_28_aarch64; do" in step
    for flag in ("--no-deps", "--only-binary=:all:", "--require-hashes", '--platform "$platform"',
                 '--python-version "$PYTHON_VERSION"', "-r requirements-yara.txt"):
        assert flag in step, flag


def test_the_compose_build_passes_yara_by_default_and_honours_an_empty_value():
    """The one service that builds the image names the argument, with the Dockerfile's default. `-` and
    not `:-`: compose substitutes the default only when the variable is unset, so an operator who sets it
    empty gets the image without yara-x they asked for, and one who sets nothing gets the one that scans."""
    from test_image_context_and_production_stack import _services
    args = _services()["migrate"]["build"]["args"]
    assert args == {"NOCTORNAL_EXTRAS": "${NOCTORNAL_EXTRAS-yara}"}, args
    default = re.fullmatch(r"\$\{NOCTORNAL_EXTRAS-(\w+)\}", args["NOCTORNAL_EXTRAS"]).group(1)
    assert f'ARG NOCTORNAL_EXTRAS="{default}"' in _text(DOCKERFILE)
    assert ":-" not in args["NOCTORNAL_EXTRAS"]


def test_the_ci_image_job_asserts_yara_x_in_the_built_image_and_its_absence_under_the_opt_out():
    """CI builds the image as a deployment does and reads it back: yara-x at the pinned version, read from
    constraints.txt and never retyped, and running under the analysis child's limits; then a build with
    the extras empty, which must not import it."""
    step = _step(_job(_ci(), "image"), "The image carries yara-x, and the opt-out does not")
    assert "set -euo pipefail" in step
    assert "want=$(sed -n 's/^yara-x==//p' constraints.txt)" in step and '[ -n "$want" ]' in step
    assert 'importlib.metadata.version("yara-x")' in step and 'os.environ["WANT"]' in step
    assert "lab_triage.selftest(" in step and 'engine.get("ok") is True' in step
    assert "docker build --build-arg NOCTORNAL_EXTRAS= -t noctornal-api:ci-noyara ." in step
    refusal = step[step.index("if docker run"):]
    assert 'noctornal-api:ci-noyara -c "import yara_x"; then' in refusal
    assert "exit 1" in refusal
