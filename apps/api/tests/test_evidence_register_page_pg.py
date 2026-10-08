"""docs/17, "the register grows with the case" (Beta 1.1).

The register counted what EVERY exhibit of the case backs (its "backs
nothing" figure was `count(*) FILTER (WHERE backs = 0)` over the case's
exhibits, each with two counting subqueries), so a page cost more as the case
grew: 2.4 s at 15,000 exhibits, and 5.7 s measured here on 15,300. What an
exhibit backs, as numbers, is counted for the rows of the PAGE now; the
case-wide figure and the "backs nothing" filter ask each exhibit only whether
it backs anything, which stops at the first live attachment.

The page must say the same things it said. The existing register tests hold
that (`test_evidence_register_pg.py`); these hold the cost:

- an exhibit with many attachments that is not on the page is not counted: the
  request reads a bounded number of entities however many it carries;
- on the page that shows it, its counts are exact.

The work is counted, not timed: index scans on `core.node` in this
transaction (`pg_stat_xact_user_tables`), with hash and merge joins and
sequential scans off so every lookup of an attached entity is one index scan.

Everything is created inside one transaction that is rolled back. Env-gated
on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from test_evidence_register_pg import _carry, _exhibit, _page
from test_evidence_register_pg import conn as _conn
from test_evidence_register_pg import world as _world

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs a migrated database")

conn = _conn
world = _world

ATTACHED = 300


def _node_scans(conn) -> int:
    return conn.execute(
        """SELECT coalesce(sum(idx_scan), 0) FROM pg_stat_xact_user_tables
            WHERE schemaname = 'core' AND relname = 'node'""").fetchone()[0]


def _lookups_only_by_index(conn) -> None:
    for setting in ("enable_hashjoin", "enable_mergejoin", "enable_seqscan",
                    "enable_bitmapscan"):
        conn.execute(f"SET LOCAL {setting} = off")


@pytest.fixture()
def crowded(conn, world):
    """Forty ordinary exhibits, each backing one entity, and an OLDER one
    that ATTACHED live claims on ATTACHED entities cite."""
    case_id, uid, n1, _n2, _edge = world
    long_ago = datetime.now(timezone.utc) - timedelta(days=100)
    heavy = _exhibit(conn, case_id, uid, title="heavy", acquired_at=long_ago)
    conn.execute(
        """INSERT INTO core.node (case_id, node_type, label, created_by)
           SELECT %s, 'IDENTITY', 'crowd-' || g, %s FROM generate_series(1, %s) g""",
        (case_id, uid, ATTACHED))
    conn.execute(
        """INSERT INTO core.assertion (case_id, node_id, basis, created_by, evidence_id)
           SELECT case_id, id, 'THIRD_PARTY_REPORT', created_by, %s
             FROM core.node WHERE case_id = %s AND label LIKE 'crowd-%%'""",
        (heavy, case_id))
    ordinary = []
    for i in range(40):
        ev = _exhibit(conn, case_id, uid, title=f"ordinary {i}",
                      acquired_at=datetime.now(timezone.utc) - timedelta(minutes=i))
        _carry(conn, case_id, uid, ev, node_id=n1)
        ordinary.append(ev)
    for table in ("core.node", "core.assertion", "core.evidence"):
        conn.execute(f"ANALYZE {table}")
    return case_id, heavy, ordinary


def test_a_page_that_does_not_show_an_exhibit_does_not_count_what_it_backs(conn, crowded):
    case_id, heavy, ordinary = crowded
    _lookups_only_by_index(conn)
    before = _node_scans(conn)
    page = _page(conn, case_id, limit=10)
    spent = _node_scans(conn) - before
    assert [str(ev) for ev in ordinary[:10]] == [i.id for i in page["items"]], \
        "the heavy exhibit is the oldest, so it is past the page"
    assert page["total"] == 41 and page["backs_nothing"] == 0
    assert spent < ATTACHED // 2, (
        f"{spent} lookups of attached entities for a page that shows none of "
        f"the {ATTACHED} the heavy exhibit has")


def test_the_page_that_shows_it_counts_what_it_backs_exactly(conn, crowded):
    case_id, heavy, _ordinary = crowded
    page = _page(conn, case_id, offset=40, limit=10)
    [item] = page["items"]
    assert item.id == str(heavy)
    assert (item.backs_nodes, item.backs_edges) == (ATTACHED, 0)


def test_the_backs_nothing_filter_stops_at_the_first_live_attachment(conn, crowded):
    case_id, heavy, ordinary = crowded
    unbacked = _exhibit(conn, case_id, uid_of(conn, case_id), title="loose")
    _lookups_only_by_index(conn)
    before = _node_scans(conn)
    page = _page(conn, case_id, backs_nothing=True)
    spent = _node_scans(conn) - before
    assert [i.id for i in page["items"]] == [str(unbacked)]
    assert page["matching"] == 1 and page["backs_nothing"] == 1
    assert spent < ATTACHED // 2, f"{spent} lookups for the filter"


def uid_of(conn, case_id):
    return conn.execute('SELECT owner_user_id FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]


def test_without_a_filter_every_exhibit_matches_and_with_one_every_unbacked(conn, crowded):
    case_id, _heavy, _ordinary = crowded
    _exhibit(conn, case_id, uid_of(conn, case_id), title="loose one")
    _exhibit(conn, case_id, uid_of(conn, case_id), title="loose two")
    everything = _page(conn, case_id)
    assert everything["matching"] == everything["total"] == 43
    loose = _page(conn, case_id, backs_nothing=True)
    assert loose["matching"] == loose["backs_nothing"] == 2
    named = _page(conn, case_id, q="loose one", backs_nothing=True)
    assert named["matching"] == 1 and named["total"] == 43
