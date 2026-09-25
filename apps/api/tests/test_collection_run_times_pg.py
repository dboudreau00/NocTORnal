"""Run start times and their order (roadmap F5.4 (a), 2026-09-24). Built
by the collection foundation (runs()'s ordering, index
collection_run_started_idx); these hold it: every run records when it
started, the listing is newest first with the runs whose start was never
recorded last, and the unfiltered listing is read through the start index
rather than sorted whole. DATABASE_URL-gated.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-tgrun-"

FEED = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>'
        b'<item><guid>run-times-1</guid><title>one</title>'
        b'<description>first</description></item></channel></rss>')


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    c.close()


def test_every_run_records_when_it_started(conn, monkeypatch):
    from noctornal_api import collection

    monkeypatch.setattr(collection, "fetch", lambda url, **kw: (FEED, 200, None, None))
    source = h.source(conn, P, kind="RSS", parser="rss",
                      base_url="https://feed.example.test/rss")
    result = collection.CollectionService(conn).run_once(source, actor_id=None)
    started, finished = conn.execute(
        "SELECT started_at, finished_at FROM collect.collection_run WHERE id = %s",
        (result.run_id,)).fetchone()
    assert started is not None and finished is not None and started <= finished


def test_runs_list_newest_first_with_unrecorded_starts_last(conn):
    from noctornal_api.collection import CollectionService

    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    now = datetime.now(timezone.utc)
    ids = {}
    for label, started in (("old", now - timedelta(hours=2)), ("none", None),
                           ("new", now - timedelta(minutes=1))):
        ids[label] = conn.execute(
            """INSERT INTO collect.collection_run
                   (source_id, status, parser_version, started_at, finished_at)
               VALUES (%s, 'OK', 't', %s, now()) RETURNING id""",
            (source, started)).fetchone()[0]
    listed = [r["id"] for r in CollectionService(conn).runs(source_id=source,
                                                            clearance="RED")]
    assert listed == [str(ids["new"]), str(ids["old"]), str(ids["none"])]


def test_the_run_history_is_read_through_the_start_index(conn):
    with conn.transaction():
        conn.execute("SET LOCAL enable_seqscan = off")
        plan = "\n".join(r[0] for r in conn.execute(
            """EXPLAIN SELECT r.id FROM collect.collection_run r
                ORDER BY r.started_at DESC NULLS LAST, r.id DESC LIMIT 25""").fetchall())
    assert "collection_run_started_idx" in plan, plan
