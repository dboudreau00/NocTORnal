"""The collection cron entry, and the lock that makes two of them safe.

## Why this file exists

Two separate things arrived on 2026-09-10 and neither could be tested the
obvious way.

`scripts/collection_poll.py` is a command, and nothing in the suite runs a
command: they need a database, an object store and, for this one, a live
site to fetch from. `test_script_invariants.py` already makes the argument
for checking scripts STATICALLY instead -- three seed scripts died on their
first line of real work while 1269 tests passed -- and the checks below are
that same instinct applied to the properties this particular script has to
have. They parse the source and assert a property, which is weaker than a
run and is the check that would actually fire.

Two of them are worth naming, because they are the ones a plausible
rewrite breaks:

  * the exit code has to be derived from the failure count, and a
    `return 0` that is not inside `--dry-run` is a cron entry that reports
    a failing collector as a healthy one -- the exact defect
    `notify_drain.py`'s docstring argues about;
  * the runner must ask `due_sources()` what is ready and must own no SQL
    of its own, because the moment it selects its own sources it is free
    to impose its own rhythm, and docs/04 asks for "randomised intervals
    with jitter, never a clean cron cadence".

The second half of the file needs Postgres, because a lock is not a thing
you can read off a syntax tree. `pg_try_advisory_lock` is SESSION-scoped
and re-entrant, so the trap in the obvious test is that two acquisitions
on ONE connection both succeed -- a test written that way passes against
no lock at all. Every lock test below uses a second connection on purpose.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
from uuid import uuid4

import pytest

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts" / "collection_poll.py"
#: `notify_drain.py` is the model this script was written from, so the
#: shape checks below compare the two rather than restating a literal --
#: a rule stated twice is a rule with a latent disagreement in it.
MODEL = REPO / "scripts" / "notify_drain.py"


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name}() is gone from {SCRIPT.name}")


# ---------------------------------------------------------------------------
# The contract the script states about itself
# ---------------------------------------------------------------------------

def test_every_flag_the_docstring_promises_is_actually_wired() -> None:
    """A documented flag that no `add_argument` defines is worse than an
    undocumented one: the operator reads the docstring, types the flag and
    gets `unrecognized arguments`, which reads as a broken install rather
    than as a stale comment."""
    import re

    tree = _tree(SCRIPT)
    documented = set(re.findall(r"--[a-z][a-z0-9-]+", ast.get_docstring(tree) or ""))
    wired = {arg.value
             for node in ast.walk(tree)
             if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute)
             and node.func.attr == "add_argument"
             for arg in node.args
             if isinstance(arg, ast.Constant) and isinstance(arg.value, str)}

    assert {"--limit", "--dry-run"} <= wired, (
        "the two flags this script exists to offer are --limit and "
        "--dry-run; one of them is no longer defined")
    assert documented <= wired, (
        f"documented but not defined: {sorted(documented - wired)}")


def _counters_join(tree: ast.Module) -> ast.JoinedStr | None:
    """The f-string inside a `" ".join(... for ...)`, if there is one.

    Matched structurally rather than by text because the point is the
    SHAPE -- one `key=value` pair per counter on one line -- and a text
    match would be satisfied by a docstring that merely mentions it.
    """
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "join"
                and isinstance(node.func.value, ast.Constant)
                and node.func.value.value == " "):
            continue
        if not node.args or not isinstance(node.args[0], ast.GeneratorExp):
            continue
        if isinstance(node.args[0].elt, ast.JoinedStr):
            return node.args[0].elt
    return None


def _joined_shape(joined: ast.JoinedStr) -> tuple[tuple[str, ...], int]:
    literals = tuple(part.value for part in joined.values
                     if isinstance(part, ast.Constant))
    fields = sum(1 for part in joined.values
                 if isinstance(part, ast.FormattedValue))
    return literals, fields


def test_the_counters_line_has_the_same_shape_as_the_drains() -> None:
    """One line, `key=value` per counter, exactly as `notify_drain.py`
    prints it.

    Not house style for its own sake. These two lines are what a cron log
    contains, and an operator greps both with the same expression; a
    runner that printed a table, or JSON, or one counter per line, would
    quietly break whatever is watching the log for `failed=`.
    """
    ours, theirs = _counters_join(_tree(SCRIPT)), _counters_join(_tree(MODEL))
    assert theirs is not None, (
        "notify_drain.py no longer prints a counters line -- this test "
        "compares against it, so fix that first")
    assert ours is not None, (
        f"{SCRIPT.name} prints no `\" \".join(f\"{{k}}={{v}}\" ...)` line")
    assert _joined_shape(ours) == _joined_shape(theirs) == (("=",), 2)


def test_the_exit_code_is_the_return_value_of_main() -> None:
    """`main()` called without `SystemExit` around it exits 0 whatever it
    returns, and the failure is invisible: the counters line still says
    `failed=3` and cron still reports success. Both scripts wire it the
    same way."""
    for path in (SCRIPT, MODEL):
        assert "raise SystemExit(main())" in ast.unparse(_tree(path)), (
            f"{path.name} does not turn main()'s return value into the "
            f"process exit code")


def _statement_lists(stmt: ast.stmt):
    for field in ("body", "orelse", "finalbody"):
        inner = getattr(stmt, field, None)
        if isinstance(inner, list):
            yield inner
    for handler in getattr(stmt, "handlers", []) or []:
        yield handler.body


def _zero_returns(body: list[ast.stmt],
                  guards: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Every `return 0`, with the `if` tests that enclose it."""
    found: list[tuple[str, ...]] = []
    for stmt in body:
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) \
                and stmt.value.value == 0:
            found.append(guards)
            continue
        if isinstance(stmt, ast.If):
            found.extend(_zero_returns(stmt.body,
                                       guards + (ast.unparse(stmt.test),)))
            found.extend(_zero_returns(stmt.orelse, guards))
            continue
        for inner in _statement_lists(stmt):
            found.extend(_zero_returns(inner, guards))
    return found


def test_a_pass_that_failed_something_cannot_exit_zero() -> None:
    """The exit code is the one channel a cron job has back to its
    operator, and a pass that failed every source and exited 0 is a
    failure reported as nothing at all.

    Checked as a property rather than by running it: the LAST thing
    `main()` does must be a return derived from the failure counter, and
    the only unconditional `return 0` allowed anywhere in it is the one
    inside `--dry-run` -- which polled nothing, so it can have failed
    nothing.
    """
    main = _function(_tree(SCRIPT), "main")
    last = main.body[-1]
    assert isinstance(last, ast.Return) and "failed" in ast.unparse(last), (
        f"main() ends with `{ast.unparse(last).splitlines()[0]}` rather "
        f"than a return derived from the failure counter")
    for guards in _zero_returns(main.body):
        assert any("dry_run" in guard for guard in guards), (
            "there is a `return 0` in main() that is not guarded by "
            "--dry-run, so some path reports success without having "
            "checked whether anything failed")


def _handler(tree: ast.Module, exception: str) -> ast.ExceptHandler:
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is not None \
                and exception in ast.unparse(node.type):
            return node
    raise AssertionError(f"{SCRIPT.name} no longer handles {exception}")


def test_a_source_another_runner_holds_is_counted_not_failed() -> None:
    """`CollectionBusy` means the work IS being done, by somebody else.

    Counting it as a failure would make a cron entry that overlaps itself
    for one minute mail its operator about a system behaving exactly as
    designed, and an alert that cries wolf is the alert people turn off.
    It must also not re-raise: one held source cannot end the pass, or the
    sources behind it go uncollected.
    """
    handler = _handler(_tree(SCRIPT), "CollectionBusy")
    body = ast.unparse(ast.Module(body=handler.body, type_ignores=[]))
    assert "'skipped'" in body, "the busy case is not counted at all"
    assert "'failed'" not in body, (
        "a source held by another runner is counted as a failure, so an "
        "overlapping cron would exit 1 on a healthy system")
    assert not any(isinstance(n, ast.Raise) for n in ast.walk(handler)), (
        "the busy case re-raises, which ends the pass and leaves every "
        "source behind it unpolled")


def test_the_runner_owns_no_sql_and_asks_what_is_due() -> None:
    """Hazard (b), enforced structurally rather than by comment.

    A runner that selected its own sources would be free to impose its own
    rhythm, and a fixed cadence is the operational-security failure docs/04
    and docs/18 both name: it flattens every source's jitter onto the
    cron's period and hands a forum admin an evenly spaced access log. With
    no query of its own the script CANNOT do that -- `due_sources()` is the
    only way it learns what to poll, and that reads the stored, jittered
    `next_due_at`.
    """
    tree = _tree(SCRIPT)
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
    assert not [c for c in calls if c.func.attr == "execute"], (
        "the runner executes SQL of its own; it must go through "
        "CollectionService so the schedule stays the source's, not the cron's")
    assert [c for c in calls if c.func.attr == "due_sources"], (
        "nothing calls due_sources() -- what is this polling, then?")


def test_the_log_line_never_names_a_source() -> None:
    """The runner reads with no clearance ceiling; the log file has no
    label at all.

    A collector has no user, so `due_sources()` is called with
    `clearance=None` and this process legitimately sees every source
    including the RED ones. A cron log is the artefact that gets shipped to
    an aggregator and pasted into a ticket, and a source's name and base
    URL are precisely what its classification protects -- the clearance
    pass of 2026-09-02 exists because a listing disclosed exactly those two
    fields. So the id is what may be printed, and the rest stays in
    `collect.collection_run` behind the API's own ceiling.
    """
    printed = {node.slice.value
               for node in ast.walk(_tree(SCRIPT))
               if isinstance(node, ast.Subscript)
               and isinstance(node.value, ast.Name) and node.value.id == "source"
               and isinstance(node.slice, ast.Constant)}
    # Checked before the subset, because a subset of nothing is every
    # subset: rename the loop variable and this test goes on passing
    # against a runner that prints the base URL of a RED source.
    assert "id" in printed, (
        "nothing is read off a source row under the name `source` -- the "
        "loop variable was renamed, so the check below no longer looks at "
        "anything the runner prints")
    assert printed <= {"id", "due_at", "health", "consecutive_failures"}, (
        f"the runner reads {sorted(printed)} off a source row; name and "
        f"base_url must not reach an unclassified log file")


def test_the_docstring_still_explains_the_cadence() -> None:
    """The one thing a maintainer must not "fix".

    Every instinct about cron entries is wrong here: a pass that polls
    nothing looks like a broken schedule, and the obvious repair -- poll
    everything each time we wake -- is the failure docs/04 names. That
    reasoning lives in the docstring and nowhere else, so this asserts it
    is still there rather than trusting it to survive a tidy-up.
    """
    doc = ast.get_docstring(_tree(SCRIPT)) or ""
    assert "cadence" in doc and "next_due_at" in doc and "due_sources" in doc, (
        "the docstring no longer explains that the cron's cadence is not "
        "the collection's -- see docs/04, 'never a clean cron cadence'")


# ---------------------------------------------------------------------------
# The advisory lock. Needs Postgres: a lock is not visible in a syntax tree.
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pg = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the lock tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

NAME_LIKE = "pollscript-%"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    with c.transaction():
        c.execute(
            """DELETE FROM collect.watch_hit WHERE document_id IN (
                   SELECT d.id FROM collect.document d JOIN collect.source s
                     ON s.id = d.source_id WHERE s.name LIKE %s)""",
            (NAME_LIKE,))
        c.execute(
            """DELETE FROM collect.document WHERE source_id IN (
                   SELECT id FROM collect.source WHERE name LIKE %s)""",
            (NAME_LIKE,))
        c.execute(
            """DELETE FROM collect.collection_run WHERE source_id IN (
                   SELECT id FROM collect.source WHERE name LIKE %s)""",
            (NAME_LIKE,))
        c.execute("DELETE FROM collect.source WHERE name LIKE %s", (NAME_LIKE,))
    c.close()


def _source(conn):
    """A source pointing at a name that cannot resolve.

    Deliberate: every poll below FAILS at the fetch, which is what a test
    that must not touch the network needs, and `run_once` treats a fetch
    failure as an ordinary outcome -- it records the run and returns. What
    is under test is whether the poll ran AT ALL, not whether it collected
    anything.

    `max_rps` is as high as the column will hold, so the durable rate
    limiter never spaces anything here. Nothing in this file polls one
    source twice, and `last_request_at` starts NULL, so it would not sleep
    today in any case -- the value is what keeps that true of a test
    somebody adds later, instead of handing them a silent five-second wait
    from the column default of 0.2.

    999 rather than a rounder 1000 because `max_rps` is numeric(6,3):
    three integer digits, so 1000 is a field overflow and every test in
    this file dies at the INSERT rather than at its assertion. The spacing
    itself is `test_collection_schedule_pg.py`'s subject, not this file's.
    """
    return conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, poll_interval_s, jitter_pct, max_rps,
                parser_key, default_reliability)
           VALUES ('WEB', %s, 'https://example.invalid/feed', 300, 20, 999,
                   'rss', 'C')
           RETURNING id""",
        (f"pollscript-{uuid4().hex[:8]}",)).fetchone()[0]


def _lock_sql(op: str) -> str:
    return f"SELECT pg_{op}(hashtextextended(%s, 0))"


@pg
def test_a_second_runner_is_refused_while_the_first_holds_the_source(conn):
    """Hazard (a): there was no lock here at all.

    Two concurrent polls of one source race in two places on an autocommit
    connection -- `_store_document` reads the digest and the previous
    version before it inserts, and `_match_watches` checks the suppression
    window before it inserts a hit -- and neither table has a unique index
    to fall back on. The overlap is the ordinary one: this script on a cron
    against an analyst pressing Run on the Feeds pane.

    The lock key comes from `_poll_lock_key` rather than being spelled out
    again here. A test that rebuilt the key from a literal would keep
    passing after the two drifted apart, which is the failure this is
    supposed to catch.
    """
    from noctornal_api.collection import (
        CollectionBusy,
        CollectionService,
        _poll_lock_key,
    )
    from noctornal_api.db import connect

    source_id = _source(conn)
    key = _poll_lock_key(source_id)
    # A SECOND connection, and that IS the test. A session advisory lock is
    # re-entrant within one session, so taking it twice on `conn` succeeds
    # both times -- a test written that way passes against no lock at all.
    other = connect()
    try:
        assert other.execute(_lock_sql("try_advisory_lock"),
                             (key,)).fetchone()[0] is True
        with pytest.raises(CollectionBusy):
            CollectionService(conn).run_once(source_id, actor_id=uuid4())
        assert conn.execute(
            "SELECT count(*) FROM collect.collection_run WHERE source_id = %s",
            (source_id,)).fetchone()[0] == 0, (
            "a refused poll wrote a run row. Nothing was polled, so a row "
            "here -- FAILED or RUNNING -- libels a source that is being "
            "collected from perfectly well by whoever holds the lock")
    finally:
        other.execute(_lock_sql("advisory_unlock"), (key,))
        other.close()


@pg
def test_two_different_sources_do_not_block_each_other(conn):
    """Why the key is the source and not one global collector lock.

    Two different sources are two different sites: the politeness that
    matters is per source (`max_rps`, `last_request_at`), and a single lock
    would make one pass as slow as the slowest feed's fetch timeout -- so a
    five-minute cron would start overlapping itself, which is the thing the
    lock exists to make safe.
    """
    from noctornal_api.collection import CollectionService, _poll_lock_key
    from noctornal_api.db import connect

    held, free = _source(conn), _source(conn)
    other = connect()
    try:
        assert other.execute(_lock_sql("try_advisory_lock"),
                             (_poll_lock_key(held),)).fetchone()[0] is True
        result = CollectionService(conn).run_once(free, actor_id=uuid4())
        # It failed at the fetch, because example.invalid does not resolve
        # and this test does not touch the network. That it produced a
        # RunResult rather than raising CollectionBusy is the whole point.
        assert result.error, "expected the unresolvable host to fail the fetch"
        assert conn.execute(
            "SELECT count(*) FROM collect.collection_run WHERE source_id = %s",
            (free,)).fetchone()[0] == 1
    finally:
        other.execute(_lock_sql("advisory_unlock"), (_poll_lock_key(held),))
        other.close()


@pg
def test_the_lock_is_released_when_the_poll_fails(conn):
    """A session lock outlives the statement that took it.

    So an exception escaping the poll would strand it for the life of the
    connection -- and in the API process, which pools nothing today but
    might, for the life of the pool. The source would then be unpollable
    until that process exited, silently: every later pass would report it
    as `skipped`, which reads as "somebody else is on it".

    What this reaches is the ORDINARY way out. `run_once` treats a fetch
    failure as an expected outcome -- it records the run and returns from
    inside the `try` -- so nothing here unwinds, and the test below is the
    one that makes an exception leave the poll.
    """
    from noctornal_api.collection import CollectionService, _poll_lock_key
    from noctornal_api.db import connect

    source_id = _source(conn)
    result = CollectionService(conn).run_once(source_id, actor_id=uuid4())
    assert result.error, "expected the unresolvable host to fail the fetch"

    other = connect()
    try:
        assert other.execute(_lock_sql("try_advisory_lock"),
                             (_poll_lock_key(source_id),)).fetchone()[0] is True, (
            "the lock survived a failed poll, so this source can never be "
            "polled again by any other process")
    finally:
        other.execute(_lock_sql("advisory_unlock"), (_poll_lock_key(source_id),))
        other.close()


@pg
def test_the_lock_is_released_when_the_poll_unwinds(conn):
    """The case the `finally` was written for, which nothing was reaching.

    A `finally` around a body that always returns normally is untested
    scaffolding, and this one is load-bearing: `run_once` re-raises on
    purpose when it cannot PERSIST what it fetched, on the reasoning that
    a fetch failure is an outcome and a failure to store is a defect. That
    re-raise is the only way an exception leaves the poll, and it is the
    only thing that can strand a session lock.

    Staged with a NUL byte in a post body, the first failure `run_once`'s
    own comment names ("a NUL byte in a post, a jsonb adaptation error, a
    dropped connection mid-loop"). Chosen over the dropped connection for
    a reason, not just because it is easier to stage: psycopg refuses to
    SEND a NUL, so
    `_store_document`'s INSERT raises with the connection still healthy,
    and the unlock in the `finally` is a statement that really runs. A
    poll killed by a dropped connection would have released the lock by
    dying -- as that `finally`'s own comment says -- and would leave this
    assertion passing against no unlock at all.

    A REAL failure rather than an injected one, which is the difference
    from `test_collection_pg`'s
    `test_a_failure_after_the_fetch_does_not_strand_the_run_at_RUNNING`:
    that one replaces `_store_document` with a function that raises and
    owns the run row's half of this fix, so the run row is deliberately
    not re-asserted here. What is only knowable from a real one is that a
    NUL byte does escape the poll at all instead of being swallowed
    somewhere between the adapter and the INSERT -- and it is the escape
    that reaches the `finally`.
    """
    import psycopg

    from noctornal_api.collection import (
        CollectionService,
        FetchResult,
        Item,
        _poll_lock_key,
    )
    from noctornal_api.db import connect

    class NulByteAdapter:
        """`test_collection_pg.StubAdapter`'s shape, kept local. Importing
        a helper across test modules would tie two files together and give
        neither of them a reason to move with the other."""

        key, version = "rss", "test"

        def fetch(self, **kw):
            return FetchResult(items=[Item(external_id="nul-1", body="a\x00b")])

    source_id = _source(conn)
    svc = CollectionService(conn, adapters={"rss": NulByteAdapter()})
    with pytest.raises(psycopg.DataError):
        svc.run_once(source_id, actor_id=uuid4())

    other = connect()
    try:
        assert other.execute(_lock_sql("try_advisory_lock"),
                             (_poll_lock_key(source_id),)).fetchone()[0] is True, (
            "an exception left run_once with the advisory lock still held; "
            "this source is unpollable by every other process until the "
            "connection that took it closes")
    finally:
        other.execute(_lock_sql("advisory_unlock"), (_poll_lock_key(source_id),))
        other.close()
