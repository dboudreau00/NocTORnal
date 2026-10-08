"""A poll killed where Python cannot unwind it leaves its run RUNNING; the next
pass marks it (docs/17, "a poll killed by SIGTERM").

The collector stops its poll child with SIGTERM and `scripts/collection_poll.py`
installs no handler for it, so the child ends at once: the `except BaseException`
that finishes a run's row never runs, and the row, committed RUNNING before the
first request, stayed RUNNING for good. `CollectionService.mark_interrupted_runs`
finishes the runs whose source's poll lock nobody holds, and the cron entry calls
it at the start of every pass.

Env-gated on DATABASE_URL. The kill test starts a real child process and ends it
with `Popen.terminate()` (SIGTERM on POSIX, TerminateProcess on Windows), so it
runs on both and needs no skip.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
PREFIX = "test-src-intr-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    ssub = f"(SELECT id FROM collect.source WHERE name LIKE '{PREFIX}%')"
    with c.transaction():
        c.execute(f"DELETE FROM collect.collection_run WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.source WHERE id IN {ssub}")
    c.close()


def _source(conn):
    return conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, default_reliability, poll_interval_s,
                jitter_pct, max_rps, parser_key, classification)
           VALUES ('RSS', %s, 'https://forum.test/feed', 'C', 300, 20, 1, 'rss',
                   'AMBER')
           RETURNING id""", (f"{PREFIX}{uuid4().hex[:6]}",)).fetchone()[0]


def _strand(conn, source_id):
    """A run as `_poll` leaves it when its process dies: committed RUNNING."""
    return conn.execute(
        """INSERT INTO collect.collection_run (source_id, status, started_at, cursor)
           VALUES (%s, 'RUNNING', now() - interval '3 minutes', '{}') RETURNING id""",
        (source_id,)).fetchone()[0]


def _run(conn, run_id):
    return conn.execute(
        "SELECT status::text, error_class, error_detail, finished_at "
        "FROM collect.collection_run WHERE id = %s", (run_id,)).fetchone()


def _service(conn):
    from noctornal_api.collection import CollectionService
    return CollectionService(conn, adapters={})


def test_a_run_no_poll_holds_any_more_is_marked_interrupted(conn):
    from noctornal_api.collection import INTERRUPTED_RUN_SENTENCE

    source_id = _source(conn)
    run_id = _strand(conn, source_id)
    before = conn.execute(
        "SELECT consecutive_failures, next_due_at, health FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()
    assert _service(conn).mark_interrupted_runs() == 1
    status, klass, detail, finished = _run(conn, run_id)
    assert (status, klass, detail) == ("FAILED", "Interrupted", INTERRUPTED_RUN_SENTENCE)
    assert finished is not None
    # Nothing about the source failed: its health and its turn are as they were.
    assert conn.execute(
        "SELECT consecutive_failures, next_due_at, health FROM collect.source WHERE id = %s",
        (source_id,)).fetchone() == before
    # And it is marked once: the second look finds nothing left.
    assert _service(conn).mark_interrupted_runs() == 0


def test_a_run_whose_poll_is_still_running_is_left_alone(conn):
    """The poll holds its source's lock for exactly as long as it runs. The lock
    test uses a second connection on purpose: a session lock is re-entrant."""
    from noctornal_api.collection import _poll_lock_key
    from noctornal_api.db import connect

    source_id = _source(conn)
    run_id = _strand(conn, source_id)
    other = connect()
    try:
        assert other.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                             (_poll_lock_key(source_id),)).fetchone()[0]
        assert _service(conn).mark_interrupted_runs() == 0
        assert _run(conn, run_id)[0] == "RUNNING"
    finally:
        other.close()
    # The poll ended (its connection closed and the lock with it): now it is marked.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _service(conn).mark_interrupted_runs() == 1:
            break
        time.sleep(0.2)
    assert _run(conn, run_id)[0] == "FAILED"


def test_sources_other_runs_and_finished_runs_are_not_touched(conn):
    live, quiet = _source(conn), _source(conn)
    finished = conn.execute(
        """INSERT INTO collect.collection_run (source_id, status, started_at, finished_at, cursor)
           VALUES (%s, 'OK', now() - interval '1 hour', now() - interval '59 minutes', '{}')
           RETURNING id""", (quiet,)).fetchone()[0]
    stranded = _strand(conn, live)
    assert _service(conn).mark_interrupted_runs() == 1
    assert _run(conn, finished)[0] == "OK" and _run(conn, stranded)[0] == "FAILED"


def test_a_poll_ended_by_sigterm_leaves_its_run_running_until_the_next_pass(conn):
    """The defect, end to end: a real poll in a real process, ended the way the
    collector ends it. Before the sweep the run stays RUNNING; after it, it does
    not."""
    source_id = _source(conn)
    child = textwrap.dedent("""
        import sys
        import time
        from noctornal_api.collection import CollectionService
        from noctornal_api.db import connect

        class Hangs:
            key, version = "rss", "test"

            def fetch(self, **kw):
                print("fetching", flush=True)
                time.sleep(120)

        conn = connect()
        CollectionService(conn, adapters={"rss": Hangs()}).run_once(
            sys.argv[1], actor_id=None)
        """)
    proc = subprocess.Popen([sys.executable, "-c", child, str(source_id)],
                            stdout=subprocess.PIPE, text=True, env=dict(os.environ))
    try:
        line = proc.stdout.readline()
        assert line.strip() == "fetching", f"the child did not reach its fetch: {line!r}"
        assert conn.execute("SELECT status::text FROM collect.collection_run "
                            "WHERE source_id = %s", (source_id,)).fetchall() == [("RUNNING",)]
        # While that poll lives, the sweep leaves it alone.
        assert _service(conn).mark_interrupted_runs() == 0
        proc.terminate()
        proc.wait(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    # The run is stranded, as the residual says...
    assert conn.execute("SELECT status::text FROM collect.collection_run "
                        "WHERE source_id = %s", (source_id,)).fetchall() == [("RUNNING",)]
    # ...until a pass looks (the server notices the dead connection within moments).
    marked = 0
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not marked:
        marked = _service(conn).mark_interrupted_runs()
        if not marked:
            time.sleep(0.25)
    assert marked == 1
    assert conn.execute("SELECT status::text, error_class FROM collect.collection_run "
                        "WHERE source_id = %s", (source_id,)).fetchall() == [
        ("FAILED", "Interrupted")]
