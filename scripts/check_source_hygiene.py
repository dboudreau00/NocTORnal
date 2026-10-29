"""Guard against the corruption modes this repository has suffered.

Four checks, all cheap:

**NUL bytes.** The editing tools have corrupted a non-ASCII literal into a NUL byte. In Python
that is a `SyntaxError`; in a served `.js` file it is a blank screen with nothing in the console,
and in a `.sql` migration a statement that silently truncates. Nothing legitimate here contains
one.

**Other control bytes.** The same corruption with another byte: a backslash and a `b` typed into
a Windows path can be written out as a BACKSPACE (0x08), which prints as a missing letter and
breaks a command copied from the docs. Tab, line feed and carriage return are text; every other
byte from 0x01 to 0x1F is refused.

**Bidirectional and invisible Unicode.** A right-to-left override or a zero-width character
inside a string or comment renders as one thing and compiles as another (CVE-2021-42574, "Trojan
Source"). In a platform whose premise is that the audit trail says what happened, source that
does not read the way it executes is refused outright. Deliberately not an all-ASCII rule:
legitimate text uses characters such as box drawing, and banning them would mean a wall of
escapes or a rule everyone disables.

**A private identity in the tree.** The project is published under one name, and its owner's
private alias must never appear in public, so file contents are read for it, not only commit
authors. The forbidden strings are assembled from fragments below, as the codepoints are spelled
numerically, because a checker must pass its own check.

Exit code 1 on any finding, with the file, line and codepoint named.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Text we author. Binary and vendored trees are skipped wholesale rather than filtered, so a new
# binary format cannot trip this by accident. The second line of suffixes and the NAMES set bring
# in every other kind of tracked text file: `start.cmd` (backslash paths, where a BACKSPACE
# hides), the Dockerfile and Caddyfile, the requirements and Alembic template, the PGP fixtures,
# the SVGs and the ignore files. A test compares this set with what git calls text, so a new
# kind of tracked file cannot slip past.
SUFFIXES = {".py", ".js", ".css", ".html", ".sql", ".md", ".toml", ".yml",
            ".yaml", ".ps1", ".sh", ".ini", ".json", ".ts",
            ".cmd", ".bat", ".txt", ".mako", ".asc", ".svg", ".example"}
NAMES = {"Dockerfile", "Caddyfile", "LICENSE", ".gitignore", ".gitattributes",
         ".dockerignore"}
SKIP_DIRS = {".git", ".claude", ".venv", "node_modules", "__pycache__", ".next",
             ".pytest_cache", ".ruff_cache", "dist", "build", ".mypy_cache",
             "egg-info"}

# Trojan Source (CVE-2021-42574) plus the zero-width characters that make two different
# identifiers look identical. Written as codepoints, not literals: spelled out, the characters
# would fail this file's own check.
BOM = 0xFEFF
DANGEROUS = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    BOM: "ZERO WIDTH NO-BREAK SPACE (BOM inside the file)",
}

# The owner's private alias, and the local part of the e-mail that goes
# with it. Assembled from fragments so that THIS file passes; matched
# case-insensitively. Deliberately not the bare first name, which is a
# common word that fixtures and test data may legitimately contain.
PRIVATE_IDENTITY = tuple("".join(parts) for parts in (
    ("tur", "pine"),
    ("jeff", "rey", "tur", "pine"),
))

# C0 control bytes other than tab (0x09), line feed (0x0A) and carriage
# return (0x0D). NUL has its own check and message above; this is the rest
# of the range. Matched on the raw bytes, before decoding, because the
# defect it exists for (a BACKSPACE where a backslash and a `b` were
# meant) decodes as valid UTF-8 and looks like a missing letter on screen.
CONTROL_BYTES = re.compile(rb"[\x01-\x08\x0b\x0c\x0e-\x1f]")
CONTROL_NAMES = {
    0x07: "BELL", 0x08: "BACKSPACE", 0x0B: "VERTICAL TAB",
    0x0C: "FORM FEED", 0x1B: "ESCAPE",
}


def control_bytes(raw: bytes) -> list[tuple[int, int, int]]:
    """(line, column, byte) of every refused control byte in `raw`, both
    counted from 1, so a finding can name the exact place to fix."""
    found = []
    for match in CONTROL_BYTES.finditer(raw):
        start = match.start()
        line_start = raw.rfind(b"\n", 0, start) + 1
        found.append((raw.count(b"\n", 0, start) + 1,
                      start - line_start + 1, raw[start]))
    return found


def files() -> list[Path]:
    out = []
    for path in REPO.rglob("*"):
        if not path.is_file() or (path.suffix.lower() not in SUFFIXES
                                  and path.name not in NAMES):
            continue
        # Relative parts, never absolute ones: a skip list names directories inside the tree,
        # and matched against the whole path, a checkout under `.claude/worktrees/<name>/` would
        # skip every file and report "0 files clean".
        if any(part in SKIP_DIRS or part.endswith(".egg-info")
               for part in path.relative_to(REPO).parts):
            continue
        out.append(path)
    return sorted(out)


def check_file(rel: str, raw: bytes) -> list[str]:
    """Every problem in one file's bytes, each naming `rel` and a line.

    Split out of `main` so the rules can be proved on bytes a test builds,
    rather than only on whatever the tree happens to contain that day.
    """
    problems: list[str] = []

    if b"\x00" in raw:
        # Report the LINE, because "there is a NUL in app.js" is not
        # actionable in a three-thousand-line file.
        line = raw[:raw.index(b"\x00")].count(b"\n") + 1
        problems.append(
            f"{rel}:{line}: NUL byte. This is almost always a non-ASCII "
            f"literal corrupted on write (docs/15); it serves as a blank "
            f"page with nothing in the console.")
        return problems

    for line, col, byte in control_bytes(raw):
        name = CONTROL_NAMES.get(byte, "control byte")
        problems.append(
            f"{rel}:{line}:{col}: {name} (0x{byte:02X}). A control byte in "
            f"a text file is a corrupted character; a BACKSPACE here is "
            f"usually a backslash and a 'b' that were written as one byte.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        problems.append(f"{rel}: not valid UTF-8 ({exc.reason} at byte "
                        f"{exc.start})")
        return problems

    # A BOM at position 0 is tolerable on Windows; anywhere else it is
    # a zero-width character hiding in the middle of a line.
    for lineno, line in enumerate(text.splitlines(), 1):
        for col, ch in enumerate(line):
            point = ord(ch)
            if point not in DANGEROUS:
                continue
            if lineno == 1 and col == 0 and point == BOM:
                continue          # a leading BOM is tolerable on Windows
            problems.append(
                f"{rel}:{lineno}:{col + 1}: {DANGEROUS[point]} "
                f"(U+{point:04X}). Source that does not read the way it "
                f"executes is refused outright (CVE-2021-42574).")

    lowered = text.lower()
    for needle in PRIVATE_IDENTITY:
        if needle in lowered:
            line = lowered[:lowered.index(needle)].count("\n") + 1
            problems.append(
                f"{rel}:{line}: the owner's private identity. It is "
                f"published under one name only; this string shipped "
                f"on the licence page of three releases before this "
                f"check existed. Replace it with the public name.")
            break
    return problems


def main() -> int:
    problems: list[str] = []
    checked = 0

    for path in files():
        checked += 1
        problems += check_file(path.relative_to(REPO).as_posix(),
                               path.read_bytes())

    # A scan that found nothing to scan is not a pass. Without this guard
    # the skip-list bug above reported success from every harness worktree.
    if checked == 0:
        print("Source hygiene: 0 files checked. The walk found nothing, "
              "which is a broken checker, not a clean tree.", file=sys.stderr)
        return 1

    if problems:
        noun = "problem" if len(problems) == 1 else "problems"
        print(f"Source hygiene: {len(problems)} {noun} in {checked} files.\n",
              file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(f"Source hygiene: {checked} files clean "
          f"(no NUL or other control bytes, no bidirectional or zero-width "
          f"characters, no private identity).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
