"""The half of docs/17 F15(i) that needed a database.

The defect was that the collector's timing lived in memory and the process
it lived in is created per request, so neither the jitter nor the rate
limit did anything. Both now live on `collect.source`.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

NAME_LIKE = "sched-%"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    with c.transaction():
        c.execute(f"DELETE FROM collect.collection_run WHERE source_id IN "
                  f"(SELECT id FROM collect.source WHERE name LIKE '{NAME_LIKE}')")
        c.execute(f"DELETE FROM collect.source WHERE name LIKE '{NAME_LIKE}'")
    c.close()


def _source(conn, *, interval=300, jitter=20, max_rps=1.0):
    return conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, poll_interval_s, jitter_pct, max_rps,
                parser_key, default_reliability)
           VALUES ('WEB', %s, 'https://example.invalid/feed', %s, %s, %s,
                   'rss', 'C')
           RETURNING id""",
        (f"sched-{uuid4().hex[:8]}", interval, jitter, max_rps)).fetchone()[0]


def test_a_new_source_is_due_immediately(conn):
    """Waiting the interval first means a newly-added source sits idle for
    its whole period and somebody concludes the collector is broken --
    which is how a working system gets "fixed"."""
    from noctornal_api.collection import CollectionService
    source_id = _source(conn)
    due = {d["id"] for d in CollectionService(conn).due_sources()}
    assert source_id in due


def test_the_schedule_is_rolled_once_and_stored_not_re_rolled_on_read(conn):
    """The defect in one test. `due_sources` used to compute the next time
    freshly on every call, so the realised interval depended on how often
    the scheduler polls -- and frequent polling collapsed the variance
    toward the floor, which is a regular cadence."""
    from noctornal_api.collection import CollectionService
    source_id = _source(conn)
    svc = CollectionService(conn)
    svc.due_sources()

    first = conn.execute(
        "SELECT next_due_at FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()[0]
    assert first is not None
    for _ in range(5):
        svc.due_sources()
    again = conn.execute(
        "SELECT next_due_at FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()[0]
    assert again == first, "reading the schedule must not change it"


def test_a_failed_run_still_reschedules(conn):
    """A source that only reschedules on success retries as fast as the
    scheduler runs the moment it breaks -- a hammering pattern aimed at a
    site that has just started refusing us."""
    from noctornal_api.collection import CollectionService
    from noctornal_api.stores import PgUserStore
    actor = PgUserStore(conn).create_user(
        f"sched-{uuid4().hex[:8]}@noctornal.test", "S", "x" * 20)
    source_id = _source(conn)
    conn.execute("UPDATE collect.source SET next_due_at = NULL WHERE id = %s",
                 (source_id,))

    result = CollectionService(conn).run_once(source_id, actor_id=actor)
    assert result.error, "example.invalid must not resolve"
    assert conn.execute(
        "SELECT next_due_at FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()[0] is not None

    with conn.transaction():
        conn.execute("DELETE FROM collect.collection_run WHERE source_id = %s",
                     (source_id,))
        conn.execute("DELETE FROM iam.app_user WHERE id = %s", (actor,))


def test_the_rate_limit_survives_a_new_service_instance(conn):
    """`RateLimiter` state used to live on the instance and
    `CollectionService` is built per request, so `max_rps` never fired at
    all. docs/04 ties it directly to not burning personas."""
    from noctornal_api.collection import RateLimiter
    source_id = _source(conn, max_rps=2.0)

    slept: list[float] = []
    first = RateLimiter(conn, sleep=slept.append)
    assert first.wait(source_id, 2.0) == 0.0

    # A completely separate instance, as a second request would build.
    second = RateLimiter(conn, sleep=slept.append)
    delay = second.wait(source_id, 2.0)
    assert delay > 0, "the gap must be measured from the stored timestamp"
    assert slept and slept[-1] == delay


def test_a_never_polled_source_is_not_reported_as_broken(conn):
    """`WHERE health <> 'OK'` looked right and was not: a source that has
    never run carries the default health with zero failures, so every newly
    added source appeared on the alert list beside a parser that genuinely
    stopped matching.

    Found by looking at the rendered list — three entries, one real. It
    matters because the list exists BECAUSE silent failure is silent, and a
    list padded with non-alerts is one people stop watching.
    """
    from noctornal_api.collection import CollectionService
    fresh = _source(conn)
    broken = _source(conn)
    conn.execute(
        "UPDATE collect.source SET consecutive_failures = 7, health = 'BROKEN',"
        " last_ok_at = now() - interval '3 days' WHERE id = %s", (broken,))

    svc = CollectionService(conn)
    unhealthy = {s["id"] for s in svc.unhealthy_sources()}
    never = {s["id"] for s in svc.never_polled_sources()}

    assert str(broken) in unhealthy
    assert str(fresh) not in unhealthy, "never polled is not broken"
    assert str(fresh) in never
    assert str(broken) not in never, "a source is in one list or the other"


def test_the_limiter_records_every_attempt_not_every_success(conn):
    """The rate limit exists to space REQUESTS, and a failed request cost
    a request."""
    from noctornal_api.collection import RateLimiter
    source_id = _source(conn)
    RateLimiter(conn, sleep=lambda _s: None).wait(source_id, 1.0)
    row = conn.execute(
        "SELECT last_request_at, last_ok_at FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()
    assert row[0] is not None and row[1] is None
