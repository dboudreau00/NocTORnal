"""A live claim is one that is neither retracted nor replaced, and every read says both.

A claim leaves the live set two ways: a retraction stamps `retracted_at`, and a dated copy that replaces it
stamps `superseded_at` (`supersede_assertion`). A read that asks only `retracted_at IS NULL` counts a claim
that was replaced as live again the moment its replacement is withdrawn (the second 2026-11 review found it
in the exhibit backing counts and flags, the retraction itself, the document pin and the ACH matrix, each
fixed with a test of its own in `test_a_replaced_claim_is_history_pg.py`).

This test keeps the class closed. In every module of the application, a line that tests `retracted_at IS
NULL` must have `superseded_at` within two lines either side, unless it is in `_DELIBERATE` below, which
names each exception by file and exact line and says why. An entry that no longer matches a line fails as
stale, so the list cannot outlive what it excuses.

SQL in migrations and in the generated schema is not read here: the one place the database asks the question
(`core.tie_confidence`) asks both, and the partial indexes name both.

Pure: reads the source.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"

_RETRACTED = re.compile(r"retracted_at\s+IS\s+NULL", re.IGNORECASE)

#: (path under noctornal_api, the line as written, stripped) -> why the line may ask only the one question.
_DELIBERATE: dict[tuple[str, str], str] = {
    ("reports.py", 'AND a.retracted_at IS NULL"""'): (
        "the ACH matrix drops a retracted claim (decision 24) and KEEPS a replaced one, marked stale, "
        "so its stance is shown and scores nothing: `ach_cells` selects `superseded_at IS NOT NULL` as "
        "`stale`, and `ach.score` takes those items out before it counts"),
}


def _sites() -> list[tuple[str, int, str, str]]:
    """(file, line number, the line stripped, the five lines around it) for every test of `retracted_at IS
    NULL` in a Python module of the application."""
    out = []
    for path in sorted(SRC.rglob("*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if _RETRACTED.search(line):
                around = "\n".join(lines[max(0, i - 2):i + 3])
                out.append((path.relative_to(SRC).as_posix(), i + 1, line.strip(), around))
    return out


def test_there_are_reads_to_check():
    """A scan that matches nothing passes by doing nothing."""
    assert len(_sites()) > 20


def test_every_read_that_asks_whether_a_claim_is_retracted_asks_whether_it_was_replaced():
    named = set(_DELIBERATE)
    missing = [f"{file}:{n}: {text}" for file, n, text, around in _sites()
               if "superseded_at" not in around and (file, text) not in named]
    assert not missing, (
        "these lines test `retracted_at IS NULL` and never ask `superseded_at`, so a claim that a dated "
        "copy replaced counts as live in them: " + "; ".join(missing))


def test_every_deliberate_exception_still_names_a_line():
    found = {(file, text) for file, _n, text, _around in _sites()}
    stale = [key for key in _DELIBERATE if key not in found]
    assert not stale, f"these exceptions excuse a line that is no longer there: {stale}"
