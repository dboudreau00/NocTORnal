"""Invariants that live in the test fixtures themselves.

## Why this file exists

Migration 0059 binds every compartment column to `iam.compartment`. From
that day a fixture that writes a key straight into a bound column with raw
SQL is refused by the database unless the key was registered first -- and
two fixtures did exactly that, in files that DID register the key, just
later, inside a different helper. On the development database the keys
had been registered by earlier runs, so the suite was green; on CI's fresh
database eight tests failed on the release commit of Alpha 5 (2026-09-09).
A per-file check ("does this file register anything?") would have passed
both files. The defect was ORDER inside one helper, so the check is per
function.

Pure -- no database. Reads the test sources.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

TESTS = Path(__file__).resolve().parent

#: A raw SQL write that sets a compartment column. Matched against the
#: string literals passed to `execute(...)` inside one function body.
_COMPARTMENT_WRITE = re.compile(
    r"(UPDATE|INSERT)[^;]*?\b(compartments|forced_compartment|"
    r"visibility_compartments)\s*(=|\))", re.I | re.S)

#: What counts as registering first: the raw INSERT the fixtures use, or
#: the service call an administrator would.
_REGISTRATION = re.compile(
    r"INSERT\s+INTO\s+iam\.compartment|register_compartment\(", re.I)

#: A write that registers nothing: the empty array.
_EMPTY_WRITE = re.compile(r"compartments\s*=\s*'\{\}'", re.I)

#: The docstring marker for a test that writes an unregistered value on
#: purpose (to seed the migration's own backfill statement, inside a
#: rolled-back transaction). Spelled out so a reader finds the reason.
_DELIBERATE = "fixture-guard: deliberate unregistered write"


def _string_constants(node: ast.AST) -> str:
    """Every string literal under `node`, joined -- so a statement split
    across adjacent literals ("UPDATE ... " "compartments = %s") reads as
    one piece of SQL."""
    return " ".join(
        n.value for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _writers_without_registration(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bad: list[str] = []
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        body_src = ast.unparse(fn)
        # A test that asserts the database refuses the write is exercising
        # 0059, not evading it; so is the one that seeds the backfill and
        # says so in its docstring.
        if "pytest.raises(" in body_src:
            continue
        if (ast.get_docstring(fn) or "").find(_DELIBERATE) >= 0:
            continue
        registered_so_far = False
        for stmt in fn.body:
            sql = _string_constants(stmt)
            src = ast.unparse(stmt)
            # A local helper named like `_register`/`_registered` counts as
            # registration when it is called before the write.
            if _REGISTRATION.search(sql) or re.search(r"\b_regist\w*\(", src):
                registered_so_far = True
            if _EMPTY_WRITE.search(sql):
                continue
            if _COMPARTMENT_WRITE.search(sql) and not registered_so_far:
                bad.append(f"{path.name}::{fn.name}")
                break
    return bad


def test_every_raw_compartment_write_registers_its_key_first():
    """A helper that writes a compartment column with raw SQL must register
    the key EARLIER IN THE SAME FUNCTION.

    The helper may take the keys as a parameter -- `_user(conn,
    compartments=("OPX",))` -- and then it must register whatever it was
    given, because it cannot know whether the caller's other helper ran
    first. That is the shape both offenders had: `_case` registered, `_user`
    wrote, and the tests called `_user` first.
    """
    offenders: list[str] = []
    for path in sorted(TESTS.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        offenders.extend(_writers_without_registration(path))
    assert not offenders, (
        "fixtures write a compartment column with raw SQL before registering "
        "the key in the same function (refused by 0059 on a fresh database): "
        f"{offenders}. Insert into iam.compartment ... ON CONFLICT (key) DO "
        "NOTHING for each key first, in that function.")


def test_the_scan_sees_the_fixtures_it_is_meant_to_guard():
    """A scan that matches nothing passes vacuously. There are known raw
    writers in the tree; the regex must find them."""
    found = 0
    for path in sorted(TESTS.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in [n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            if _COMPARTMENT_WRITE.search(_string_constants(fn)):
                found += 1
    assert found >= 5, f"the scan found only {found} raw compartment writers"


# Every email prefix a test file creates accounts under, however it spells
# it: a PREFIX constant, an EMAIL_LIKE pattern, or an f-string address.
_PREFIX_DEFS = (
    re.compile(r'^\s*(?:PREFIX|EMAIL_PREFIX)\s*=\s*"([a-z0-9]+-)"', re.M),
    re.compile(r'"([a-z0-9]+-)%@noctornal\.test"'),
    re.compile(r'f"([a-z0-9]+-)\{uuid4\(\)\.hex\[:\d+\]\}@noctornal\.test"'),
)


def test_every_email_prefix_belongs_to_one_file():
    """Teardowns delete by email prefix, and an append-only ledger (an
    exhibit, a custody row) pins what one file leaves behind. Two files on
    one prefix therefore break each other in a full run and never alone:
    the dual-control tests took `dch-` and `dcp-`, both already the
    deception tests', and every dual-control teardown then failed on the
    deception exhibit it tried to delete (F9, 2026-09-24)."""
    owners: dict[str, set[str]] = {}
    for path in sorted(TESTS.glob("test_*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in _PREFIX_DEFS:
            for match in pattern.finditer(text):
                owners.setdefault(match.group(1), set()).add(path.name)
    assert len(owners) >= 100, f"the scan found only {len(owners)} prefixes"
    shared = {prefix: sorted(files) for prefix, files in owners.items()
              if len(files) > 1}
    assert not shared, f"email prefixes used by more than one test file: {shared}"
