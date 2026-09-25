"""Migrations 0098 to 0101 going down (F15.2 to F15.4, 2026-09-24): legal
hold overrides deletion, so a downgrade that would drop a held case's
lookups, answers or batches refuses; 0098 refuses while the ledger that
names its providers exists; and 0101 cancels what it would
otherwise strand in the queue. Every schema change runs inside a
transaction that is rolled back (the test_roles_and_pii_pg.py pattern), so
the database the rest of the suite uses never sees it.

The fetcher and the routes are fakes. **The email prefix is `lkmig-`.**
Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from outbound_support import (
    DATABASE_URL,
    MISP_GREEN_BODY,
    FakeFetcher,
    fetched,
    lookup_world,
    make_selector,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lkmig-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
DOMAIN = {"kind": "VALUE", "selector_type": "DOMAIN", "value": "example.org"}


class _RollBack(Exception):
    pass


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _migration(conn, stem: str):
    path = next(VERSIONS.glob(f"{stem}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def _none_world(conn):
    return lookup_world(conn, PREFIX, level="NONE", adapter="misp_rest",
                        fetcher=FakeFetcher(fetched(200, MISP_GREEN_BODY)))


def _batch(conn, w):
    ids = [make_selector(conn, w.case_id, "DOMAIN", f"d{i}.example.org") for i in range(2)]
    svc, selection = w.service(conn), {"selector_ids": [str(i) for i in ids]}
    plan = svc.plan(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                    operation="attribute_search", selection=selection)
    return svc.commit_batch(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                            operation="attribute_search", selection=selection,
                            confirm_exposure="NONE", note="Enrich the list we were given.",
                            plan_digest=plan["plan_digest"])["batch_id"]


def _hold(conn, case_id):
    conn.execute('UPDATE core."case" SET legal_hold = true, legal_hold_reason = %s '
                 'WHERE id = %s', ("litigation", case_id))


def test_0101_refuses_while_a_held_case_has_a_batch(conn):
    import psycopg
    w = _none_world(conn)
    _batch(conn, w)
    with pytest.raises(psycopg.errors.RaiseException, match="legal hold"), \
            conn.transaction():
        _hold(conn, w.case_id)
        _migration(conn, "0101").downgrade()


def test_0101_cancels_what_it_would_strand_in_the_queue(conn):
    w = _none_world(conn)
    batch = _batch(conn, w)
    with pytest.raises(_RollBack), conn.transaction():
        _migration(conn, "0101").downgrade()
        rows = conn.execute("SELECT state, refusal FROM ingest.lookup WHERE case_id = %s",
                            (w.case_id,)).fetchall()
        assert rows and set(rows) == {("CANCELLED", "batch support removed by downgrade")}
        assert conn.execute("SELECT to_regclass('ingest.lookup_batch')").fetchone()[0] is None
        _migration(conn, "0101").upgrade()
        raise _RollBack()
    assert conn.execute("SELECT count(*) FROM ingest.lookup WHERE batch_id = %s",
                        (batch,)).fetchone()[0] == 2


def test_0100_refuses_while_a_held_case_has_an_answer(conn):
    import psycopg
    w = _none_world(conn)
    w.service(conn).request(w.case_id, DOMAIN, provider_id=w.provider.id,
                            operation="attribute_search", user_id=w.analyst,
                            confirm_exposure="NONE")
    with pytest.raises(psycopg.errors.RaiseException, match="0100.*legal hold"), \
            conn.transaction():
        _hold(conn, w.case_id)
        _migration(conn, "0101").downgrade()
        _migration(conn, "0100").downgrade()


def test_0099_refuses_while_a_held_case_has_a_lookup(conn):
    import psycopg
    w = lookup_world(conn, PREFIX, fetcher=FakeFetcher(fetched(200, b"{}")))
    w.service(conn).request(w.case_id, DOMAIN, provider_id=w.provider.id,
                            operation="domain_report", user_id=w.analyst,
                            confirm_exposure="VENDOR", authorised_by=w.owner,
                            authorisation_note="needed")
    with pytest.raises(psycopg.errors.RaiseException, match="0099.*legal hold"), \
            conn.transaction():
        _hold(conn, w.case_id)
        for stem in ("0101", "0100", "0099"):
            _migration(conn, stem).downgrade()


def test_0098_refuses_while_the_ledger_exists(conn):
    import psycopg
    with pytest.raises(psycopg.errors.RaiseException, match="downgrade 0099 first"), \
            conn.transaction():
        _migration(conn, "0098").downgrade()


def test_the_lookup_revisions_round_trip_with_their_guards(conn):
    with pytest.raises(_RollBack), conn.transaction():
        for stem in ("0101", "0100", "0099", "0098"):
            _migration(conn, stem).downgrade()
        assert conn.execute("SELECT to_regclass('ingest.provider')").fetchone()[0] is None
        assert conn.execute(
            "SELECT count(*) FROM iam.permission WHERE key IN ('lookup.request', "
            "'lookup.authorise')").fetchone()[0] == 0
        for stem in ("0098", "0099", "0100", "0101"):
            _migration(conn, stem).upgrade()
        triggers = {r[0] for r in conn.execute(
            "SELECT tgname FROM pg_trigger WHERE tgrelid IN ('ingest.lookup'::regclass, "
            "'ingest.provider'::regclass, 'ingest.lookup_batch'::regclass) "
            "AND NOT tgisinternal").fetchall()}
        assert {"lookup_guarded", "provider_guarded", "provider_starts_unapproved"} <= triggers
        raise _RollBack()
