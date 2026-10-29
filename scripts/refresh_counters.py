"""Rewrite the counters the live documents quote, from the tree.

The numbers are generated: this script rewrites them, a test asserts that running it changes
nothing, and the tolerance is zero, because a hand-kept count drifts. It is the arrangement
`db/schema.sql` has with `scripts/dump_schema.py`: the file is checked in, a tool regenerates it,
and CI fails on a diff.

    python scripts/refresh_counters.py            # rewrite
    python scripts/refresh_counters.py --check    # report, change nothing

Only the regions in `CHECKED` are live, and inside them only the shapes in `SUBSTITUTIONS`.
`ROADMAP-REMAINING.md` is mostly dated `**State (` records, which must never be rewritten, so only
the text above its second `**State (` heading is live; the changelog is not read at all. A number
that cannot be derived from the tree does not belong in a live document, which is why no counter
here is "collected items": it needs a pytest collection. Per-release totals stay in
`release/CHANGELOG.md`.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: `def test_` at any indentation, sync or async -- the definition the
#: documents' figure is held to, and the one they state beside it.
_TEST_DEF = re.compile(r"^\s*(?:async )?def test_\w+", re.M)

_TEST_ROOTS = (ROOT / "apps" / "api" / "tests",
               ROOT / "packages" / "ontology" / "tests")


def test_function_count() -> int:
    n = 0
    for root in _TEST_ROOTS:
        for path in sorted(root.rglob("test_*.py")):
            n += len(_TEST_DEF.findall(path.read_text(encoding="utf-8")))
    if n < 500:
        raise SystemExit(f"only counted {n} test functions. Is this the wrong root?")
    return n


def revision_files() -> list[Path]:
    return sorted((ROOT / "db" / "migrations" / "versions").glob("0*.py"))


def revision_count() -> int:
    n = len(revision_files())
    if n < 50:
        raise SystemExit(f"only {n} migration version files. Is this the wrong root?")
    return n


def head_revision() -> str:
    """The highest four-digit prefix in `versions/`.

    Derived from the filenames rather than from Alembic, so this script
    stays importable without the package installed. `test_doc_invariants`
    separately asserts the quoted head against the real Alembic chain
    head, so a file named out of order cannot make both agree on a lie.
    """
    return max(p.name[:4] for p in revision_files())


def package_version() -> str:
    text = (ROOT / "apps" / "api" / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("apps/api/pyproject.toml has no version")
    return match.group(1)


#: The one place the completion figure is WORKED OUT: the roadmap states
#: it as the unweighted mean of its ten per-phase rows. Every other
#: document quotes it, and quoting is what drifted -- ~92% in
#: ARCHITECTURE, ~95% in release/README, 92.8% here, all at once.
_COMPLETION_LINE = re.compile(r"(?i)^\s*(?:#+\s*)?overall\b|^\|\s*completion\s*\|")
_PERCENT = re.compile(r"(\d{1,3}(?:\.\d)?)%")


def completion_figure() -> str:
    for line in (ROOT / "ROADMAP-REMAINING.md").read_text(
            encoding="utf-8").splitlines():
        if _COMPLETION_LINE.search(line):
            found = _PERCENT.search(line)
            if found:
                return found.group(1)
    raise SystemExit("ROADMAP-REMAINING.md states no overall completion figure")


def _values() -> dict[str, str]:
    return {
        "tests": str(test_function_count()),
        "revisions": str(revision_count()),
        "head": head_revision(),
        "version": package_version(),
        "completion": completion_figure(),
    }


#: (name, pattern). Group 1 is the number to replace; every other group is
#: context that is put back unchanged. Deliberately narrow: a shape a
#: document uses to state a live figure, never a bare number.
SUBSTITUTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # FOUR digits and up. Three-digit figures are narrative history --
    # "it had 673 passing tests and shipped" -- and the first run of this
    # script rewrote that 673 to the current total before anyone read the
    # diff. A generator loose in prose destroys the records it walks past.
    ("tests", re.compile(r"\b(\d{4,5})(?=(?:\s|%20)(?:tests|passing)\b)")),
    # `Alembic head` followed by any whitespace, a newline included: the roadmap's live paragraph
    # wraps between the two words.
    ("head", re.compile(r"(Alembic head\s+[`*]{0,2})(\d{4})")),
    # `at revision NNNN` is not here: ARCHITECTURE's "surveyed ... at revision 0052" lines are dated
    # records of when a section was written.
    # A revision range, `0001`-`0061` or `db/migrations/versions/0001`-`0061`, with any dash.
    ("head", re.compile(r"(0001`\s*[-–—]\s*`)(\d{4})")),
    ("revisions", re.compile(
        r"\b(\d{2,3})(?=\s+(?:Alembic\s+)?(?:revisions|migrations)\b)")),
    ("version", re.compile(r"(?<=\bversion )(\d+\.\d+\.\d+)\b")),
)

#: file -> how much of it is a live claim. `None` is the whole file; a
#: string is a marker, and everything from its SECOND occurrence onward is
#: treated as dated history and left alone.
CHECKED: dict[str, str | None] = {
    "README.md": None,
    "ARCHITECTURE.md": None,
    "CONVENTIONS.md": None,
    "release/README.md": None,
    "ROADMAP-REMAINING.md": "**State (",
}


def _say(line: str) -> None:
    """Print a line of a document without dying on it.

    A Windows console's cp1252 cannot encode README.md's box-drawing characters, and failing at the
    report would leave a refresh half applied. The encoding of a terminal is not a reason to stop.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(line.encode(encoding, "replace").decode(encoding, "replace"))


def _live_region(text: str, marker: str | None) -> int:
    """Index one past the last character of the live region."""
    if marker is None:
        return len(text)
    first = text.find(marker)
    if first < 0:
        return len(text)
    second = text.find(marker, first + len(marker))
    return len(text) if second < 0 else second


def _rewrite(text: str, values: dict[str, str]) -> tuple[str, int]:
    """Apply every substitution, returning the new text and how many
    numbers were seen (whether or not they changed)."""
    seen = 0

    def apply(name: str, pattern: re.Pattern[str], body: str) -> str:
        nonlocal seen

        def one(match: re.Match[str]) -> str:
            nonlocal seen
            seen += 1
            groups = match.groups()
            # The number is the LAST group; anything before it is context
            # the lookbehind could not carry (a backtick, bold markers).
            prefix = "".join(g for g in groups[:-1] if g)
            return prefix + values[name]

        return pattern.sub(one, body)

    for name, pattern in SUBSTITUTIONS:
        text = apply(name, pattern, text)
    # The completion figure, only on a line that announces one. A bare
    # percentage is a per-phase score or a historical aside ('this line
    # read ~95% while the row above it meant 90.8%') and is left alone.
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if not _COMPLETION_LINE.search(line):
            continue
        found = _PERCENT.search(line)
        if not found:
            continue
        seen += 1
        lines[i] = (line[:found.start(1)] + values["completion"]
                    + line[found.end(1):])
    return "\n".join(lines), seen


def refresh(check: bool = False) -> int:
    values = _values()
    stale: list[str] = []
    total_seen = 0
    for name, marker in CHECKED.items():
        path = ROOT / name
        # Bytes, decoded: the text exactly as stored, CRLF included, so the write below can keep
        # each file's line endings. Path.read_text has no `newline` before Python 3.13.
        raw = path.read_bytes().decode("utf-8")
        crlf = "\r\n" in raw
        text = raw.replace("\r\n", "\n")
        cut = _live_region(text, marker)
        live, history = text[:cut], text[cut:]
        new_live, seen = _rewrite(live, values)
        total_seen += seen
        if new_live != live:
            stale.append(name)
            # Every change, printed. A tool that rewrites prose can walk
            # over a dated record without noticing, and the only cheap
            # defence is that a person sees what it did.
            for before, after in zip(live.splitlines(),
                                     new_live.splitlines(), strict=False):
                if before != after:
                    _say(f"  {name}")
                    _say(f"    - {before.strip()[:100]}")
                    _say(f"    + {after.strip()[:100]}")
            if not check:
                out = new_live + history
                path.write_text(out.replace("\n", "\r\n") if crlf else out,
                                encoding="utf-8", newline="")
    if total_seen < 10:
        print(f"only {total_seen} counter claims found: the shapes moved "
              f"and this tool is checking nothing", file=sys.stderr)
        return 1
    if stale:
        verb = "are stale" if check else "were refreshed"
        print(f"counters {verb} in: {', '.join(stale)}")
        print("  " + ", ".join(f"{k}={v}" for k, v in sorted(values.items())))
        return 1 if check else 0
    print(f"counters are current in all {len(CHECKED)} documents "
          f"({total_seen} claims): "
          + ", ".join(f"{k}={v}" for k, v in sorted(values.items())))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="report stale counters and change nothing")
    return refresh(check=parser.parse_args().check)


if __name__ == "__main__":
    raise SystemExit(main())
