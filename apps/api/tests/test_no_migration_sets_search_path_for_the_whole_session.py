"""No migration sets `search_path` for the whole session.

Alembic runs each revision in a transaction of its own on ONE connection (`env.py`,
`transaction_per_migration=True`). A plain `SET search_path` outlives the COMMIT that ends a revision, so
the path the last revision chose was the one the next revision started at, in an `alembic upgrade head`
and in a downgrade alike, while a revision run in a process of its own started at the connection's
default. `SET LOCAL search_path` ends with the revision's transaction, so every revision starts at the
session's own path and a name it leaves unqualified cannot resolve through a schema an earlier revision
chose. A fresh schema was unchanged by the move (docs/17, Closed index).

A function attribute (`CREATE FUNCTION ... SECURITY DEFINER SET search_path = pg_catalog, pg_temp`,
`ALTER FUNCTION ... SET search_path`) is not a statement: it is a security control that pins a definer's
path, `SET LOCAL` is a syntax error there, and the scan leaves it alone, because a statement begins a
string or follows a `;`.

Pure: reads the tree only, so it runs on both CI legs.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

MIGRATIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"

#: A session-wide `SET [SESSION] search_path` at the start of a statement: at the start of a string or
#: after a `;`, past white space and whole-line `--` comments.
SESSION_WIDE = re.compile(
    r"(?:\A|;)[ \t\r\n]*(?:--[^\n]*\n[ \t\r\n]*)*SET[ \t\r\n]+(?:SESSION[ \t\r\n]+)?search_path\b",
    re.I)
#: The function form of the same thing: `set_config('search_path', ..., false)`.
SESSION_WIDE_CALL = re.compile(r"set_config\(\s*'search_path'\s*,[^)]*,\s*false\s*\)", re.I)
TRANSACTION_WIDE = re.compile(r"\bSET[ \t\r\n]+LOCAL[ \t\r\n]+search_path\b", re.I)

#: The statements the released revisions carry, each `SET LOCAL` since 2026-11-15.
RELEASED_STATEMENTS = 77


def _docstrings(tree: ast.AST) -> set[int]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                found.add(id(body[0].value))
    return found


def _sql_strings(path: Path) -> list[tuple[int, str]]:
    """Every string in a revision except its docstrings, an f-string with `{}` for each field."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = _docstrings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            skip.update(id(v) for v in node.values)
    out = []
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        if isinstance(node, ast.JoinedStr):
            out.append((node.lineno, "".join(
                v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append((node.lineno, node.value))
    return out


def session_wide(sql: str) -> int:
    return len(SESSION_WIDE.findall(sql)) + len(SESSION_WIDE_CALL.findall(sql))


def _revisions() -> list[Path]:
    return sorted(MIGRATIONS.glob("0*.py"))


def test_no_migration_issues_a_session_wide_set_search_path():
    offenders = [f"{path.name}:{line}"
                 for path in _revisions()
                 for line, sql in _sql_strings(path)
                 for _ in range(session_wide(sql))]
    assert offenders == [], (
        f"{len(offenders)} session-wide SET search_path in "
        f"{len({o.split(':')[0] for o in offenders})} revisions: {offenders}. Say SET LOCAL "
        "search_path: a session-wide SET carries into the next revision of the same run")


def test_the_scan_sees_what_it_is_meant_to_see():
    """A pattern that matches nothing passes the test above by finding nothing."""
    assert len(_revisions()) >= 180, f"only {len(_revisions())} revisions under {MIGRATIONS}"
    for statement in ("SET search_path = core;",
                      "CREATE TABLE x ();\nSET search_path = core;",
                      "-- c\nSET SESSION search_path TO core;",
                      "\n  set search_path = lab, core, public;",
                      "SELECT set_config('search_path', 'core', false)"):
        assert session_wide(statement) == 1, statement
    for statement in ("SET LOCAL search_path = core;",
                      "CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER "
                      "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;",
                      "CREATE FUNCTION f() RETURNS trigger\nLANGUAGE plpgsql SECURITY DEFINER\n"
                      "SET search_path = pg_catalog, pg_temp AS $$ BEGIN RETURN NEW; END $$;",
                      "ALTER FUNCTION f() SET search_path = pg_catalog;",
                      "ALTER FUNCTION f() SECURITY INVOKER RESET search_path;",
                      "SELECT set_config('search_path', 'core', true)"):
        assert session_wide(statement) == 0, statement


def test_the_released_revisions_still_pin_a_path_for_their_own_transaction():
    """The fix is SET LOCAL, not deleting the statement: the revisions that name their objects
    unqualified need the path, for their own transaction."""
    pinned = sum(len(TRANSACTION_WIDE.findall(sql))
                 for path in _revisions() for _, sql in _sql_strings(path))
    assert pinned >= RELEASED_STATEMENTS, pinned
