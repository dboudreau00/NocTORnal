"""The collected-document sweep's declaration, and what keeps it out of the
cron loop (docs/17 F30, 2026-10-02).

Pure: no database. Reads the module's refusals, the shipped deployment files
and the operator documentation.

What these hold:

- a real run's authority reference is refused when blank, a placeholder, an
  answer rather than a reference, or too short, and accepted when it is a
  reference (the L1 pattern: recorded, never verified);
- nothing the deployment ships runs the sweep: not the production cron loop,
  not the other loops, not the installers or launchers, not the Dockerfile. It
  destroys third-party data, and the owner decides who runs it under which
  authority (docs/16 L4); a loop that runs itself on a timer nobody watches
  is how data disappears on a Sunday;
- the script is a dry run unless it is told otherwise;
- the operator documentation names the variables and flags the code reads.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "retention_sweep.py"
README = ROOT / "infra" / "production" / "README.md"

#: Files whose non-comment lines schedule or start things. Markdown is left
#: out: it may say why the sweep is not scheduled.
SCHEDULERS = (
    ROOT / "infra" / "production" / "compose.yml",
    ROOT / "infra" / "docker-compose.yml",
    ROOT / "release" / "install.sh",
    ROOT / "release" / "install.ps1",
    ROOT / "scripts" / "launch.sh",
    ROOT / "scripts" / "launch.ps1",
    ROOT / "Dockerfile",
)


def _live_lines(path: Path) -> str:
    """The file without its comment lines: what runs, not what is said."""
    return "\n".join(line for line in path.read_text(encoding="utf-8").splitlines()
                     if not line.strip().startswith("#"))


# --- the declaration -------------------------------------------------------

@pytest.mark.parametrize("value", [None, "", "   ", "\t\n"])
def test_a_missing_authority_is_refused(value):
    from noctornal_api.retention_sweep import SweepRefused, validate_reference

    with pytest.raises(SweepRefused) as refused:
        validate_reference(value)
    assert "NOCTORNAL_RETENTION_SWEEP_AUTHORITY is not set" in str(refused.value)
    assert "Nothing was destroyed" in str(refused.value)


@pytest.mark.parametrize("value", [
    "replace-me-sweep-authority", "REPLACE-ME", "please change-me soon",
    "changeme", "a placeholder"])
def test_a_placeholder_authority_is_refused(value):
    from noctornal_api.retention_sweep import SweepRefused, validate_reference

    with pytest.raises(SweepRefused) as refused:
        validate_reference(value)
    assert "placeholder" in str(refused.value)


@pytest.mark.parametrize("value", [
    "true", "YES", "1", "ok", "none", "n/a", "tbd", "todo", "abcd", "L4-7"])
def test_an_answer_or_a_stub_is_not_a_reference(value):
    """`true` is what somebody types to make an error go away; a reference is
    what somebody has to possess (docs/16 L1)."""
    from noctornal_api.retention_sweep import SweepRefused, validate_reference

    with pytest.raises(SweepRefused) as refused:
        validate_reference(value)
    assert "not a reference an auditor can follow" in str(refused.value)


@pytest.mark.parametrize("value", [
    "RETSCHED-2026-014", "  retention schedule v3, section 4  ",
    "https://counsel.example.test/instructions/2026-77"])
def test_a_reference_is_accepted_and_returned_trimmed(value):
    from noctornal_api.retention_sweep import validate_reference

    assert validate_reference(value) == value.strip()


def test_the_declaration_is_read_from_the_environment_it_is_given():
    from noctornal_api.retention_sweep import (
        AUTHORITY_ENV,
        SweepRefused,
        declared_authority,
    )

    assert declared_authority({AUTHORITY_ENV: "RETSCHED-2026-014"}) == "RETSCHED-2026-014"
    with pytest.raises(SweepRefused):
        declared_authority({})
    with pytest.raises(SweepRefused):
        declared_authority({AUTHORITY_ENV: "replace-me-reference"})


def test_a_refusal_quotes_no_value():
    """The reference is the operator's own words, and a refusal goes to a log:
    it names the variable and what is wrong, never what was typed."""
    from noctornal_api.retention_sweep import SweepRefused, validate_reference

    typed = "replace-me-secretish-ticket-4417"
    with pytest.raises(SweepRefused) as refused:
        validate_reference(typed)
    assert "4417" not in str(refused.value) and typed not in str(refused.value)


# --- the cron loop ---------------------------------------------------------

@pytest.mark.parametrize("path", SCHEDULERS, ids=lambda p: p.name)
def test_nothing_the_deployment_ships_runs_the_sweep(path):
    """Not the production cron loop, nor the other loops, nor an installer or
    launcher: the sweep destroys third-party data and an operator runs it
    (docs/17 F30; docs/00 decision 157)."""
    assert path.exists(), path
    assert "retention_sweep" not in _live_lines(path), (
        f"{path.relative_to(ROOT)} runs the retention sweep. It is operator-run: "
        f"the owner decides who runs it under which authority (docs/16 L4).")


def test_the_scan_looks_at_the_loop_that_runs_the_other_jobs():
    """A guard that reads the wrong file passes for ever. The production
    compose's cron service runs the three drains, so the file is the one."""
    live = _live_lines(ROOT / "infra" / "production" / "compose.yml")
    for job in ("scripts/notify_drain.py", "scripts/collection_poll.py",
                "scripts/lookup_drain.py"):
        assert job in live, job


# --- the script ------------------------------------------------------------

def _tree() -> ast.Module:
    return ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))


def test_the_script_is_a_dry_run_unless_told_otherwise():
    tree = _tree()
    flags = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument" and node.args
                and isinstance(node.args[0], ast.Constant)):
            flags[node.args[0].value] = {kw.arg: kw.value for kw in node.keywords}
    apply_flag = flags["--apply"]
    assert ast.unparse(apply_flag["action"]) == "'store_true'", (
        "--apply must be a switch that is off unless given")
    assert "default" not in apply_flag, "--apply must not default to anything"


def test_the_script_runs_as_the_retention_system_purpose():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "connect_system(SystemPurpose.RETENTION)" in text


def test_the_script_names_no_dash_and_no_bracketed_plural():
    """The shipped-copy rules every script is held to; read here as well so a
    failure names this file's own words."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text
    assert not re.search(r"\(s\)", text)


# --- the documentation -----------------------------------------------------

def test_the_operator_documentation_names_what_the_code_reads():
    from noctornal_api import retention_sweep as rs

    text = README.read_text(encoding="utf-8")
    assert "Retention sweep" in text
    for needle in (rs.AUTHORITY_ENV, rs.ACTOR_ENV, "scripts/retention_sweep.py",
                   "--apply", "--actor", rs.EVENT, "retention_sweep_current"):
        assert needle in text, f"infra/production/README.md does not say {needle}"
    assert "not in the cron loop" in text.replace("\r\n", "\n").replace("\n", " ")
