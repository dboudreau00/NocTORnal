"""Batch lookups (F15.4, 2026-09-24): to your own
instance (NONE) only, previewed with nothing sent or written, committed
against the digest of what was previewed, cancellable, and reported from
the rows the reader can read, with no totals that would count what they
cannot.

The fetcher and the routes are fakes; nothing reaches a provider. **The
email prefix is `lkbatch-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import pytest

from outbound_support import (
    DATABASE_URL,
    MISP_GREEN_BODY,
    FakeFetcher,
    assign,
    client as make_client,
    fetched,
    lookup_world,
    make_node,
    make_selector,
    make_user,
    session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lkbatch-"
NOTE = "Enrich the domains from the takedown list."


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _world(conn, n=3, **kw):
    w = lookup_world(conn, PREFIX, level=kw.pop("level", "NONE"),
                     adapter=kw.pop("adapter", "misp_rest"),
                     fetcher=FakeFetcher(fetched(200, MISP_GREEN_BODY)), **kw)
    ids = [make_selector(conn, w.case_id, "DOMAIN", f"d{i}.example.org") for i in range(n)]
    return w, ids


def _plan(w, conn, ids, **kw):
    return w.service(conn).plan(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                                operation="attribute_search",
                                selection={"selector_ids": [str(i) for i in ids]}, **kw)


def _commit(w, conn, ids, digest, **kw):
    return w.service(conn).commit_batch(
        w.case_id, user_id=w.analyst, provider_id=w.provider.id, operation="attribute_search",
        selection={"selector_ids": [str(i) for i in ids]}, confirm_exposure="NONE",
        note=kw.pop("note", NOTE), plan_digest=digest, **kw)


def _counts(conn, case_id):
    return conn.execute("SELECT (SELECT count(*) FROM ingest.lookup WHERE case_id = %s), "
                        "(SELECT count(*) FROM ingest.lookup_batch WHERE case_id = %s)",
                        (case_id, case_id)).fetchone()


def test_a_batch_goes_to_your_own_instance_only(conn):
    from noctornal_api import lookups
    w, ids = _world(conn, level="VENDOR", adapter="virustotal_v3")
    with pytest.raises(lookups.LookupRefused) as caught:
        w.service(conn).plan(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                             operation="domain_report",
                             selection={"selector_ids": [str(i) for i in ids]})
    assert caught.value.code == "batch_needs_none"


def test_the_database_holds_a_batch_to_none(conn):
    import psycopg
    w, _ids = _world(conn)
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("""INSERT INTO ingest.lookup_batch (case_id, provider_id, operation,
                            exposure_level, requested_by, note, plan_digest, planned, cached)
                        VALUES (%s, %s, 'attribute_search', 'VENDOR', %s, %s, %s, 1, 0)""",
                     (w.case_id, w.provider.id, w.analyst, NOTE, b"\x00" * 32))


def test_a_plan_sends_nothing_and_writes_nothing(conn):
    w, ids = _world(conn)
    before = _counts(conn, w.case_id)
    plan = _plan(w, conn, ids)
    assert (plan["eligible"], plan["to_send"], plan["cached"]) == (3, 3, 0)
    assert plan["summary"] == "3 lookups to send, 0 already answered and fresh, 0 refused."
    assert _counts(conn, w.case_id) == before and not w.fetcher.calls


def test_a_selector_the_planner_cannot_see_is_omitted_entirely(conn):
    w, ids = _world(conn)
    node = make_node(conn, w.case_id, w.owner, "Red holder", classification="RED")
    hidden = make_selector(conn, w.case_id, "DOMAIN", "hidden.example.org", node_id=node)
    plan = _plan(w, conn, [*ids, hidden])
    assert plan["eligible"] == 3 and plan["refused"] == []
    assert str(hidden) not in repr(plan)


def test_a_refused_selector_is_named_with_its_reason(conn):
    w, ids = _world(conn)
    node = make_node(conn, w.case_id, w.owner, "Amber holder", classification="AMBER")
    amber = make_selector(conn, w.case_id, "DOMAIN", "amber.example.org", node_id=node)
    plan = _plan(w, conn, [*ids, amber])
    assert plan["eligible"] == 3
    assert [(r["selector_id"], r["code"][:7]) for r in plan["refused"]] == [
        (str(amber), "egress:")]


def test_more_than_the_limit_is_refused(conn, monkeypatch):
    from noctornal_api import lookups
    w, ids = _world(conn)
    monkeypatch.setattr(lookups, "BATCH_MAX", 2)
    with pytest.raises(lookups.LookupRefused) as caught:
        _plan(w, conn, ids)
    assert caught.value.code == "too_many"


def test_a_commit_queues_what_was_previewed(conn):
    w, ids = _world(conn)
    plan = _plan(w, conn, ids)
    got = _commit(w, conn, ids, plan["plan_digest"])
    assert (got["queued"], got["cached"]) == (3, 0) and not w.fetcher.calls
    rows = conn.execute("SELECT state, exposure_level, batch_id FROM ingest.lookup "
                        "WHERE case_id = %s", (w.case_id,)).fetchall()
    assert {r[:2] for r in rows} == {("QUEUED", "NONE")}
    assert {str(r[2]) for r in rows} == {got["batch_id"]}
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s AND action = "
                        "'LOOKUP_BATCH_QUEUED'", (got["batch_id"],)).fetchone()[0] == 1


def test_a_commit_refuses_a_plan_that_changed(conn):
    from noctornal_api import lookups
    w, ids = _world(conn)
    plan = _plan(w, conn, ids)
    extra = make_selector(conn, w.case_id, "DOMAIN", "late.example.org")
    with pytest.raises(lookups.LookupRefused) as caught:
        _commit(w, conn, [*ids, extra], plan["plan_digest"])
    assert caught.value.code == "plan_changed"
    assert _counts(conn, w.case_id) == (0, 0)


def test_a_commit_needs_a_note(conn):
    from noctornal_api import lookups
    w, ids = _world(conn)
    plan = _plan(w, conn, ids)
    with pytest.raises(lookups.LookupRefused) as caught:
        _commit(w, conn, ids, plan["plan_digest"], note="because")
    assert caught.value.code == "note_required"


def test_a_fresh_answer_is_cached_in_the_batch_not_sent(conn):
    w, ids = _world(conn)
    first = w.service(conn).request(w.case_id, {"kind": "SELECTOR", "selector_id": str(ids[0])},
                                    provider_id=w.provider.id, operation="attribute_search",
                                    user_id=w.analyst, confirm_exposure="NONE")
    assert first["status"] == 200
    plan = _plan(w, conn, ids)
    assert (plan["cached"], plan["to_send"]) == (1, 2)
    got = _commit(w, conn, ids, plan["plan_digest"])
    assert (got["queued"], got["cached"]) == (2, 1)


def test_cancel_stops_what_is_still_queued(conn):
    from noctornal_api import lookups
    w, ids = _world(conn)
    plan = _plan(w, conn, ids)
    batch = _commit(w, conn, ids, plan["plan_digest"])["batch_id"]
    other, _ = make_user(conn, PREFIX)
    assign(conn, w.case_id, other, "ANALYST")
    svc = w.service(conn)
    with pytest.raises(lookups.LookupRefused) as caught:
        svc.cancel_batch(w.case_id, batch, user_id=other, reason="not mine")
    assert caught.value.code == "not_yours"
    assert svc.cancel_batch(w.case_id, batch, user_id=w.owner, reason="wrong list") == 3
    assert {r[0] for r in conn.execute("SELECT state FROM ingest.lookup WHERE batch_id = %s",
                                       (batch,)).fetchall()} == {"CANCELLED"}
    with pytest.raises(lookups.LookupRefused, match="already cancelled"):
        svc.cancel_batch(w.case_id, batch, user_id=w.owner, reason="again")


def test_progress_counts_only_what_the_reader_can_read_and_never_the_totals(conn):
    w, ids = _world(conn)
    node = make_node(conn, w.case_id, w.owner, "Holder", classification="GREEN")
    conn.execute("UPDATE core.selector SET node_id = %s WHERE id = %s", (node, ids[0]))
    plan = _plan(w, conn, ids)
    _commit(w, conn, ids, plan["plan_digest"])
    conn.execute("UPDATE core.node SET classification = 'RED' WHERE id = %s", (node,))
    (item,) = w.service(conn).batches(w.case_id, user_id=w.analyst)
    assert item["states"] == {"QUEUED": 2}
    assert "planned" not in item and "cached" not in item
    low, _ = make_user(conn, PREFIX, clearance="CLEAR")
    assign(conn, w.case_id, low, "ANALYST")
    assert w.service(conn).batches(w.case_id, user_id=low) == []


def test_the_plan_route_takes_the_selection_in_the_body(conn, monkeypatch):
    from noctornal_api import lookups
    w, ids = _world(conn)

    class Faked(lookups.LookupService):
        def __init__(self, c, **_kw):
            super().__init__(c, fetcher=w.fetcher, route_for=w.route_for)

    monkeypatch.setattr(lookups, "LookupService", Faked)
    r = make_client().post(f"/api/v1/cases/{w.case_id}/lookups/plan",
                           headers=session(conn, w.analyst_email),
                           json={"provider_id": str(w.provider.id),
                                 "operation": "attribute_search",
                                 "selection": {"selector_ids": [str(i) for i in ids]}})
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] == 3


def test_the_list_says_who_may_cancel_what_is_still_queued(conn):
    """The console offers Cancel where cancel_batch takes it: the requester
    or a lead investigator, while rows are queued
    (2026-09-25)."""
    from uuid import UUID

    from outbound_support import assign, make_user
    w, ids = _world(conn)
    plan = _plan(w, conn, ids)
    _commit(w, conn, ids, plan["plan_digest"])
    svc = w.service(conn)
    (mine,) = svc.batches(w.case_id, user_id=w.analyst)
    assert mine["yours"] and mine["can_cancel"]
    (lead,) = svc.batches(w.case_id, user_id=w.owner)
    assert not lead["yours"] and lead["can_cancel"]
    other, _ = make_user(conn, PREFIX, clearance="AMBER")
    assign(conn, w.case_id, other, "ANALYST")
    (theirs,) = svc.batches(w.case_id, user_id=other)
    assert not theirs["yours"] and not theirs["can_cancel"]
    svc.cancel_batch(w.case_id, UUID(mine["id"]), user_id=w.analyst, reason="not needed now")
    (after,) = svc.batches(w.case_id, user_id=w.analyst)
    assert not after["can_cancel"]
