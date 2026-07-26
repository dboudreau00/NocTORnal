"""Guard against the corruption modes this repo has actually suffered.

Two checks, both cheap, both encoding something that cost real debugging
time and is recorded in docs/15.

**NUL bytes.** The editing tools on the development machine have more than
once corrupted a non-ASCII literal into a NUL byte. In Python that is a
`SyntaxError` you find immediately; in a served `.js` file it is a blank
screen with nothing in the console, and in a `.sql` migration it is a
statement that silently truncates. Nothing legitimate in this tree
contains one.

**Bidirectional and invisible Unicode.** A right-to-left override or a
zero-width character inside a string or comment renders as one thing and
compiles as another (CVE-2021-42574, "Trojan Source"). In a platform
whose whole premise is that the audit trail says what happened, source
that does not read the way it executes is a category of problem worth
refusing outright rather than reviewing carefully.

Deliberately NOT an all-ASCII rule: the docs and the UI legitimately use
em dashes and box-drawing characters, and banning them would mean either
a wall of escapes or a rule everyone disables.

Exit code 1 on any finding, with the file, line and codepoint named --
"something is wrong somewhere" is not an error message.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Text we author. Binary and vendored trees are skipped wholesale rather
# than filtered, so a new binary format cannot trip this by accident.
SUFFIXES = {".py", ".js", ".css", ".html", ".sql", ".md", ".toml", ".yml",
            ".yaml", ".ps1", ".sh", ".ini", ".json", ".ts"}
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".next",
             ".pytest_cache", ".ruff_cache", "dist", "build", ".mypy_cache",
             "egg-info"}

# Trojan Source (CVE-2021-42574) plus the zero-width characters that make
# two different identifiers look identical.
#
# Written as CODEPOINTS, not literals, and that is not fussiness: with the
# characters spelled out this file fails its own check. A linter that
# cannot be run against itself is a linter nobody trusts.
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


def files() -> list[Path]:
    out = []
    for path in REPO.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SUFFIXES:
            continue
        if any(part in SKIP_DIRS or part.endswith(".egg-info")
               for part in path.parts):
            continue
        out.append(path)
    return sorted(out)


def main() -> int:
    problems: list[str] = []
    checked = 0

    for path in files():
        rel = path.relative_to(REPO).as_posix()
        raw = path.read_bytes()
        checked += 1

        if b"\x00" in raw:
            # Report the LINE, because "there is a NUL in app.js" is not
            # actionable in a three-thousand-line file.
            line = raw[:raw.index(b"\x00")].count(b"\n") + 1
            problems.append(
                f"{rel}:{line}: NUL byte. This is almost always a non-ASCII "
                f"literal corrupted on write (docs/15); it serves as a blank "
                f"page with nothing in the console.")
            continue

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            problems.append(f"{rel}: not valid UTF-8 ({exc.reason} at byte "
                            f"{exc.start})")
            continue

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

    if problems:
        print(f"Source hygiene: {len(problems)} problem(s) in {checked} files.\n",
              file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(f"Source hygiene: {checked} files clean "
          f"(no NUL bytes, no bidirectional or zero-width characters).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
