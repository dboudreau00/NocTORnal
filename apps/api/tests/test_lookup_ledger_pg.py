"""The lookup ledger as a record (F15.3, 2026-09-24):
never deleted, what was asked and by whose authority fixed, the state
machine held by the database, and retention that empties values, notes
and bodies while every row, fingerprint and attempt stays.

The fetcher and the routes are fakes; nothing reaches a provider. **The
email prefix is `lkledg-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import pytest

from outbound_support import (
    DATABASE_URL,
    MISP_GREEN_BODY,
    FakeFetcher,
    fetched,
    lookup_world,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lkledg-"
DOMAIN = {"kind": "VALUE", "selector_type": "DOMAIN", "value": "example.org"}


class _NeverCommit(Exception):
    pass


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _age(conn, case_id):
    """Expired, as test_governance_pg.py ages a case: created a month before
    a retention date already past (case_retention_sane)."""
    conn.execute('''UPDATE core."case" SET retention_until = '2024-01-01',
                                      review_due = '2023-12-31',
                                      created_at = '2023-12-01'
                    WHERE id = %s''', (case_id,))


def _answered(conn):
    w = lookup_world(conn, PREFIX, level="NONE", adapter="misp_rest",
                     fetcher=FakeFetcher(fetched(200, MISP_GREEN_BODY)))
    got = w.service(conn).request(w.case_id, DOMAIN, provider_id=w.provider.id,
                                  operation="attribute_search", user_id=w.analyst,
                                  confirm_exposure="NONE")
    return w, got


@pytest.mark.parametrize("table", ["ingest.lookup", "ingest.lookup_result",
                                   "ingest.lookup_attempt"])
def test_nothing_in_the_ledger_is_deleted(conn, table):
    import psycopg
    w, _got = _answered(conn)
    with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
        conn.execute(f"DELETE FROM {table} WHERE provider_id = %s", (w.provider.id,))
    with pytest.raises(psycopg.errors.RaiseException):
        with conn.transaction():
            conn.execute(f"TRUNCATE {table} CASCADE")
            raise _NeverCommit


@pytest.mark.parametrize("column,value", [("query_fingerprint", b"\x00" * 32),
                                          ("classification", "AMBER"),
                                          ("exposure_level", "PUBLIC"),
                                          ("operation", "other")])
def test_what_was_asked_and_of_whom_is_fixed(conn, column, value):
    import psycopg
    w, got = _answered(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="fixed"), conn.transaction():
        conn.execute(f"UPDATE ingest.lookup SET {column} = %s WHERE id = %s",
                     (value, got["lookup_id"]))


def test_an_answered_lookup_does_not_move_again(conn):
    import psycopg
    _w, got = _answered(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="cannot move"), \
            conn.transaction():
        conn.execute("UPDATE ingest.lookup SET state = 'QUEUED', result_id = result_id "
                     "WHERE id = %s", (got["lookup_id"],))


def test_the_first_send_time_and_the_attempts_only_go_forward(conn):
    import psycopg
    _w, got = _answered(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="first sent"), conn.transaction():
        conn.execute("UPDATE ingest.lookup SET sent_at = sent_at - interval '1 day' "
                     "WHERE id = %s", (got["lookup_id"],))
    with pytest.raises(psycopg.errors.RaiseException, match="only rise"), conn.transaction():
        conn.execute("UPDATE ingest.lookup SET attempts = 0 WHERE id = %s",
                     (got["lookup_id"],))


def test_the_value_changes_only_when_retention_empties_it(conn):
    import psycopg
    _w, got = _answered(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="retention"), conn.transaction():
        conn.execute("UPDATE ingest.lookup SET query_value = 'other.example' WHERE id = %s",
                     (got["lookup_id"],))
    with pytest.raises(psycopg.errors.RaiseException, match="retention"), conn.transaction():
        conn.execute("UPDATE ingest.lookup_result SET raw_body = '' WHERE id = %s",
                     (got["result_id"],))


def test_an_answer_is_kept_as_it_came_back(conn):
    import psycopg
    _w, got = _answered(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="as it came back"), \
            conn.transaction():
        conn.execute("UPDATE ingest.lookup_result SET outcome = 'NOT_FOUND' WHERE id = %s",
                     (got["result_id"],))
    with pytest.raises(psycopg.errors.RaiseException, match="recorded once"), \
            conn.transaction():
        conn.execute("UPDATE ingest.lookup_result SET findings_total = findings_total + 1 "
                     "WHERE id = %s", (got["result_id"],))


def test_retention_empties_the_ledger_and_keeps_every_row(conn):
    from noctornal_api.retention import RetentionService
    w, got = _answered(conn)
    w.service(conn).request(
        w.case_id, dict(DOMAIN, value="later.example.org"), provider_id=w.provider.id,
        operation="attribute_search", user_id=w.analyst, confirm_exposure="NONE")
    _age(conn, w.case_id)
    result = RetentionService(conn).purge_due(actor_id=w.owner, authority="test schedule",
                                              case_id=w.case_id)
    assert result.lookups_purged == 2 and result.lookup_results_purged == 2
    rows = conn.execute("SELECT query_value, purged_at IS NOT NULL, octet_length("
                        "query_fingerprint), state FROM ingest.lookup WHERE case_id = %s "
                        "ORDER BY requested_at", (w.case_id,)).fetchall()
    assert [r[:3] for r in rows] == [("", True, 32), ("", True, 32)]
    assert rows[0][3] == "ANSWERED"
    assert conn.execute("SELECT count(*) FROM ingest.lookup_attempt WHERE provider_id = %s",
                        (w.provider.id,)).fetchone()[0] == 2
    body, summary = conn.execute("SELECT octet_length(raw_body), summary FROM "
                                 "ingest.lookup_result WHERE id = %s",
                                 (got["result_id"],)).fetchone()
    assert (body, summary) == (0, {})


def test_a_queued_lookup_is_cancelled_before_it_is_emptied(conn):
    from noctornal_api.retention import RetentionService
    w, _got = _answered(conn)
    conn.execute("UPDATE ingest.provider SET quota_per_minute = 1 WHERE id = %s",
                 (w.provider.id,))
    queued = w.service(conn).request(
        w.case_id, dict(DOMAIN, value="later.example.org"), provider_id=w.provider.id,
        operation="attribute_search", user_id=w.analyst, confirm_exposure="NONE",
        queue_if_limited=True)
    assert queued["status"] == 202
    _age(conn, w.case_id)
    RetentionService(conn).purge_due(actor_id=w.owner, authority="test schedule",
                                     case_id=w.case_id)
    assert conn.execute("SELECT state, refusal FROM ingest.lookup WHERE id = %s",
                        (queued["lookup_id"],)).fetchone() == ("CANCELLED", "purged")


def test_a_case_under_legal_hold_keeps_its_lookups(conn):
    from noctornal_api.retention import RetentionService
    w, got = _answered(conn)
    _age(conn, w.case_id)
    conn.execute('UPDATE core."case" SET legal_hold = true, legal_hold_reason = %s '
                 'WHERE id = %s', ("litigation", w.case_id))
    try:
        result = RetentionService(conn).purge_due(actor_id=w.owner, authority="schedule",
                                                  case_id=w.case_id)
        assert result.lookups_purged == 0
        assert conn.execute("SELECT query_value FROM ingest.lookup WHERE id = %s",
                            (got["lookup_id"],)).fetchone()[0] == "example.org"
    finally:
        conn.execute('UPDATE core."case" SET legal_hold = false, legal_hold_reason = NULL '
                     'WHERE id = %s', (w.case_id,))
