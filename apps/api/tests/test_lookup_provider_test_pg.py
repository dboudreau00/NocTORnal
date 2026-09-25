"""The provider test (F15.3, 2026-09-24): a
canary with no case and no case material, run by one administrator
whatever the provider's exposure, counted against the quota like any send,
and answered with a status only: never an error detail, an excerpt or a
body.

The fetcher and the routes are fakes; nothing reaches a provider. **The
email prefix is `lktest-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from outbound_support import (
    DATABASE_URL,
    FakeFetcher,
    client as make_client,
    fetched,
    http_error,
    lookup_world,
    session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lktest-"
KEY = "sk_test_" + "k" * 40
VT_FILE = (Path(__file__).parent / "fixtures" / "lookups"
           / "virustotal_file_200.json").read_bytes()


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _world(conn, answer=None, **kw):
    return lookup_world(conn, PREFIX, fetcher=FakeFetcher(answer or fetched(200, VT_FILE)),
                        **kw)


def test_a_vendor_provider_is_tested_by_one_administrator_with_no_case_material(conn):
    from noctornal_api import lookup_adapters
    w = _world(conn)
    got = w.service(conn).test_provider(w.provider.id, actor_id=w.admin)
    assert got == {"state": "ANSWERED", "http_status": 200, "outcome": "FOUND",
                   "error_class": None}
    (call,) = w.fetcher.calls
    op, stype, value = lookup_adapters.ADAPTERS["virustotal_v3"].canary
    assert value.lower() in call["url"].lower()
    row = conn.execute("SELECT case_id, subject_kind, classification, result_id, "
                       "authorised_by FROM ingest.lookup WHERE provider_id = %s",
                       (w.provider.id,)).fetchone()
    assert row == (None, "CANARY", "CLEAR", None, None)
    assert conn.execute("SELECT count(*) FROM ingest.lookup_result WHERE provider_id = %s",
                        (w.provider.id,)).fetchone()[0] == 0
    detail = conn.execute("SELECT detail FROM audit.event WHERE object_id = %s AND action = "
                          "'PROVIDER_TESTED'", (w.provider.id,)).fetchone()[0]
    assert set(detail) == {"state", "http_status", "outcome"}


def test_the_test_counts_against_the_quota(conn):
    from noctornal_api import lookups
    w = _world(conn, quota_per_minute=1)
    w.service(conn).test_provider(w.provider.id, actor_id=w.admin)
    with pytest.raises(lookups.QuotaExhausted):
        w.service(conn).test_provider(w.provider.id, actor_id=w.admin)


def test_a_refused_key_answers_a_status_and_never_the_body(conn):
    w = _world(conn, http_error(401, f'{{"error": {{"code": "WrongCredentialsError", '
                                     f'"message": "bad {KEY}"}}}}'))
    got = w.service(conn).test_provider(w.provider.id, actor_id=w.admin)
    assert got["state"] == "FAILED" and got["error_class"] == "credential_refused"
    assert KEY not in repr(got) and "WrongCredentials" not in repr(got)
    assert conn.execute("SELECT status FROM ingest.provider WHERE id = %s",
                        (w.provider.id,)).fetchone()[0] == "LOCKED"


@pytest.mark.parametrize("why", ["switch", "key", "route"])
def test_the_test_sends_nothing_it_should_not(conn, monkeypatch, why):
    from noctornal_api import lookups, providers
    from outbound_support import route_for_factory
    w = _world(conn)
    svc = w.service(conn)
    code = {"switch": "switch_off", "key": "no_key", "route": "no_route"}[why]
    if why == "switch":
        monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "off")
    elif why == "key":
        providers.ProviderVault(conn).clear(w.provider.id, actor_id=w.admin, reason="rotate")
    else:
        svc = w.service(conn, route_for=route_for_factory({}))
    with pytest.raises(lookups.LookupRefused) as caught:
        svc.test_provider(w.provider.id, actor_id=w.admin)
    assert caught.value.code == code and not w.fetcher.calls


def test_the_drain_and_retention_never_select_a_canary(conn):
    from noctornal_api import lookups
    from noctornal_api.retention import RetentionService
    w = _world(conn)
    w.service(conn).test_provider(w.provider.id, actor_id=w.admin)
    due = RetentionService(conn).due()
    canary = conn.execute("SELECT id FROM ingest.lookup WHERE provider_id = %s",
                          (w.provider.id,)).fetchone()[0]
    assert canary not in {item.object_id for item in due}
    report = lookups.drain(conn, service=w.service(conn))
    assert w.provider.key not in report["providers"]


def test_the_test_route_is_an_administrators(conn, monkeypatch):
    from noctornal_api import lookups
    w = _world(conn)

    class Faked(lookups.LookupService):
        def __init__(self, c, **_kw):
            super().__init__(c, fetcher=w.fetcher, route_for=w.route_for)

    monkeypatch.setattr(lookups, "LookupService", Faked)
    client = make_client()
    path = f"/api/v1/providers/{w.provider.id}/test"
    assert client.post(path, headers=session(conn, w.analyst_email)).status_code == 403
    r = client.post(path, headers=session(conn, w.admin_email))
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "ANSWERED"
