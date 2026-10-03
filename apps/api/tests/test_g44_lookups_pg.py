"""A case-level hold, placed through the product, keeps the case's lookups
(evidence-case-hold-unreachable, unit g44, 2026-10-03), and the due list leaves
out a lookup above the reader (g44-due-labelled-records, same date).

`test_lookup_ledger_pg.py` holds the lookup purge to the case's hold with a
raw UPDATE, which is all there was until the product could place one. This
places it with `RetentionService.set_case_legal_hold`, the call behind
`POST /retention/cases/{id}/legal-hold`, and lifts it the same way.

The fetcher is a fake; nothing reaches a provider. **The email prefix is
`g44lk-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

from datetime import datetime, timezone

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

PREFIX = "g44lk-"
DOMAIN = {"kind": "VALUE", "selector_type": "DOMAIN", "value": "example.org"}


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def test_a_case_hold_keeps_the_lookups_and_lifting_it_lets_retention_empty_them(conn):
    from noctornal_api.retention import RetentionService
    w = lookup_world(conn, PREFIX, level="NONE", adapter="misp_rest",
                     fetcher=FakeFetcher(fetched(200, MISP_GREEN_BODY)))
    got = w.service(conn).request(w.case_id, DOMAIN, provider_id=w.provider.id,
                                  operation="attribute_search", user_id=w.analyst,
                                  confirm_exposure="NONE")
    conn.execute('''UPDATE core."case" SET retention_until = '2024-01-01',
                                      review_due = '2023-12-31',
                                      created_at = '2023-12-01'
                    WHERE id = %s''', (w.case_id,))
    svc = RetentionService(conn)
    svc.set_case_legal_hold(w.case_id, actor_id=w.owner, on=True,
                            reason="preservation order, g44 test",
                            lifter_ceiling=("RED", []))
    held = svc.purge_due(actor_id=w.owner, authority="schedule", case_id=w.case_id)
    assert (held.lookups_purged, held.lookup_results_purged) == (0, 0)
    assert held.held_back >= 2
    assert conn.execute("SELECT query_value FROM ingest.lookup WHERE id = %s",
                        (got["lookup_id"],)).fetchone()[0] == "example.org"

    svc.set_case_legal_hold(w.case_id, actor_id=w.owner, on=False,
                            reason="order discharged, g44 test",
                            lifter_ceiling=("RED", []))
    freed = svc.purge_due(actor_id=w.owner, authority="schedule", case_id=w.case_id)
    assert freed.lookups_purged == 1 and freed.lookup_results_purged == 1
    assert conn.execute("SELECT query_value FROM ingest.lookup WHERE id = %s",
                        (got["lookup_id"],)).fetchone()[0] == ""


def test_the_due_list_leaves_out_a_lookup_and_its_answer_above_the_caller(conn):
    """g44-due-labelled-records: `/retention/due` listed every lookup and
    answer of a case to any retention.read holder, whatever their labels,
    though the ledger itself hides what is above them. A lookup is never
    above AMBER (the lookup_never_above_amber check), so the reader below it is
    one cleared CLEAR."""
    from types import SimpleNamespace

    from noctornal_api.http.routers.governance import _visible_due
    from noctornal_api.retention import RetentionService
    from outbound_support import make_user

    w = lookup_world(conn, PREFIX, level="NONE", adapter="misp_rest",
                     fetcher=FakeFetcher(fetched(200, MISP_GREEN_BODY)))
    got = w.service(conn).request(w.case_id, DOMAIN, provider_id=w.provider.id,
                                  operation="attribute_search", user_id=w.analyst,
                                  confirm_exposure="NONE")
    # Make both rows AMBER, as a lookup of an AMBER subject is, with the
    # guards off (a lookup is fixed once asked; the teardown does the same).
    with conn.transaction():
        for table in ("ingest.lookup", "ingest.lookup_result"):
            conn.execute(f"ALTER TABLE {table} DISABLE TRIGGER USER")
        try:
            conn.execute("UPDATE ingest.lookup SET classification = 'AMBER' "
                         "WHERE id = %s", (got["lookup_id"],))
            conn.execute("UPDATE ingest.lookup_result SET classification = 'AMBER' "
                         "WHERE lookup_id = %s", (got["lookup_id"],))
        finally:
            for table in ("ingest.lookup", "ingest.lookup_result"):
                conn.execute(f"ALTER TABLE {table} ENABLE TRIGGER USER")
    items = [i for i in RetentionService(conn).due(
        case_id=w.case_id, as_of=datetime(2099, 1, 1, tzinfo=timezone.utc))
        if i.object_type in ("lookup", "lookup_result")]
    assert {i.object_type for i in items} == {"lookup", "lookup_result"}

    below, _ = make_user(conn, PREFIX, clearance="CLEAR")
    kept, withheld = _visible_due(conn, SimpleNamespace(user_id=below), items,
                                  [w.case_id])
    assert kept == [] and withheld and withheld[0]["incomplete"] is True
    kept, _ = _visible_due(conn, SimpleNamespace(user_id=w.analyst), items,
                           [w.case_id])
    assert {i.object_type for i in kept} == {"lookup", "lookup_result"}
