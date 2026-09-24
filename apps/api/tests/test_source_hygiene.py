"""`scripts/check_source_hygiene.py`, proved on bytes built here.

CI runs the script over the tree, which proves only that today's tree is
clean. It never proved the script can see what it claims to look for, and
the one byte class it did not look for shipped in all seven tagged
releases, Alpha 1 to Alpha 5.2: `release/INSTALL.md` carried a literal
BACKSPACE (0x08) where `scripts\\bootstrap.py` was meant, in both Windows
recovery commands, so each printed as `scriptsootstrap.py` and failed when
copied (Alpha 6 pre-release check, 2026-09-23). The check now refuses every
C0 control byte except tab, line feed and carriage return, in every text
file the repository tracks, and these tests hold it to that.

Pure: imports the script by path; reads files and runs `git ls-files`,
writes nothing.
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "check_source_hygiene.py"


def _hygiene():
    spec = importlib.util.spec_from_file_location("check_source_hygiene", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: Every byte the check refuses: 0x01 to 0x08, 0x0B, 0x0C, 0x0E to 0x1F.
#: NUL is refused too, by its own older check with its own message.
REFUSED = [b for b in range(0x01, 0x20) if b not in (0x09, 0x0A, 0x0D)]


@pytest.mark.parametrize("byte", REFUSED, ids=lambda b: f"0x{b:02X}")
def test_every_control_byte_is_refused_with_its_place(byte: int):
    hygiene = _hygiene()
    raw = b"first line\r\nsecond " + bytes([byte]) + b"line\n"
    problems = hygiene.check_file("doc.md", raw)
    assert len(problems) == 1, problems
    # Line 2, column 8: the byte after "second ", counted from 1, so the
    # finding points at the character to fix.
    assert problems[0].startswith("doc.md:2:8: "), problems[0]
    assert f"0x{byte:02X}" in problems[0], problems[0]


def test_the_backspace_that_shipped_is_named_as_one():
    """The exact corruption: a backslash and a `b` written as one byte."""
    hygiene = _hygiene()
    raw = b"> .venv\\Scripts\\python scripts\x08ootstrap.py create-user\n"
    problems = hygiene.check_file("release/INSTALL.md", raw)
    assert len(problems) == 1, problems
    assert "BACKSPACE (0x08)" in problems[0], problems[0]
    column = raw.index(b"\x08") + 1
    assert problems[0].startswith(f"release/INSTALL.md:1:{column}: "), problems[0]


def test_tab_line_feed_and_carriage_return_are_text():
    hygiene = _hygiene()
    assert hygiene.check_file("a.py", b"x = 1\t# tab\r\ny = 2\n") == []


def test_a_nul_is_still_reported_once_as_a_nul():
    """The older NUL check keeps its message, and a NUL is not reported a
    second time as a control byte."""
    hygiene = _hygiene()
    problems = hygiene.check_file("app.js", b"ok\nbad \x00 \x08\n")
    assert len(problems) == 1, problems
    assert "NUL byte" in problems[0]


def test_install_md_spells_the_windows_commands_in_full():
    """The two commands the backspace broke, as a reader copies them."""
    text = (ROOT / "release" / "INSTALL.md").read_text(encoding="utf-8")
    assert text.count("scripts\\bootstrap.py create-user") >= 1, (
        "the Windows create-user recovery command is gone or broken")
    assert text.count("scripts\\bootstrap.py session") >= 1, (
        "the Windows TOTP bypass command is gone or broken")


def _tracked_text_files() -> list[str] | None:
    """Every tracked path git classifies as text, or None where there is no
    git history to ask (a release tarball made by `git archive`)."""
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        return None
    out = subprocess.run([git, "ls-files", "--eol", "-z"], cwd=ROOT,
                         capture_output=True, check=True).stdout
    tracked = []
    for entry in out.split(b"\0"):
        if not entry:
            continue
        info, _, path = entry.partition(b"\t")
        # `i/-text` is git's own verdict of binary content (the PNGs, the
        # PDF, the PPTX); `i/lf`, `i/crlf`, `i/mixed` and an empty file's
        # bare `i/` are text.
        if info.split()[0] != b"i/-text":
            tracked.append(path.decode("utf-8"))
    return tracked


def test_every_tracked_text_file_is_scanned():
    """The walk chose files by a list of suffixes, so `start.cmd`, the
    Dockerfile, the Caddyfile, the requirements, the PGP fixtures, the SVGs
    and the ignore files were never read for a control byte, although the
    brief was every tracked text file (Alpha 6 pre-release check,
    2026-09-23). Git decides what is text; the checker must cover all of
    it, so a new kind of tracked file fails here until it is added."""
    tracked = _tracked_text_files()
    if tracked is None:
        pytest.skip("no git history here to list the tracked files from")
    hygiene = _hygiene()
    scanned = {p.relative_to(hygiene.REPO).as_posix() for p in hygiene.files()}
    missing = sorted(p for p in tracked
                     if p not in scanned and (ROOT / p).is_file())
    assert not missing, (
        f"tracked text files the hygiene check never reads: {missing}. Add "
        f"their suffix to SUFFIXES or their name to NAMES.")


def test_a_control_byte_in_a_file_without_a_known_suffix_is_found(tmp_path,
                                                                  monkeypatch):
    """The widened walk, on a tree built here: a batch file and a
    Dockerfile each carrying a BACKSPACE are both reported."""
    hygiene = _hygiene()
    (tmp_path / "start.cmd").write_bytes(b"python scripts\x08ootstrap.py\r\n")
    (tmp_path / "Dockerfile").write_bytes(b"COPY scripts\x08ootstrap.py /app\n")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x08")
    monkeypatch.setattr(hygiene, "REPO", tmp_path)
    assert [p.name for p in hygiene.files()] == ["Dockerfile", "start.cmd"]
    assert hygiene.main() == 1


def test_the_tree_passes_its_own_hygiene_check(capsys):
    """What CI's source-hygiene job runs, run here too, so a control byte
    fails the suite where a developer runs it and not only in CI."""
    hygiene = _hygiene()
    code = hygiene.main()
    out = capsys.readouterr()
    assert code == 0, out.err
    assert "no NUL or other control bytes" in out.out
