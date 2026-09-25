"""Provider quotas and the provider's own refusals (F15.3,
2026-09-24): counted in Postgres from the append-only attempt rows
under the provider's row lock, exact calendar windows, a queued share that
leaves interactive work room, a cooldown on 429 and a lock on 401 or 403.

The fetcher and the routes are fakes; nothing reaches a provider. **The
email prefix is `lkquota-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from outbound_support import (
    DATABASE_URL,
    MISP_GREEN_BODY,
    FakeFetcher,
    fetched,
    http_error,
    lookup_world,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lkquota-"
KEY = "sk_test_" + "k" * 40


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _world(conn, *answers, **kw):
    return lookup_world(conn, PREFIX, level="NONE", adapter="misp_rest",
                        fetcher=FakeFetcher(*(answers or (fetched(200, MISP_GREEN_BODY),))),
                        **kw)


def _ask(w, conn, n, **kw):
    return w.service(conn).request(
        w.case_id, {"kind": "VALUE", "selector_type": "DOMAIN", "value": f"q{n}.example.org"},
        provider_id=w.provider.id, operation="attribute_search", user_id=w.analyst,
        confirm_exposure="NONE", **kw)


def test_the_queued_share_leaves_interactive_room():
    from noctornal_api import lookups
    assert lookups._share(5, 20) == 4
    assert lookups._share(1, 90) == 1
    assert lookups._share(100, 0) == 100


def test_an_interactive_send_may_fill_the_window_and_the_next_is_refused(conn):
    from noctornal_api import lookups
    w = _world(conn, quota_per_minute=2)
    t = datetime.now(timezone.utc)
    assert _ask(w, conn, 1, now=t)["status"] == 200
    assert _ask(w, conn, 2, now=t + timedelta(seconds=10))["status"] == 200
    with pytest.raises(lookups.QuotaExhausted) as caught:
        _ask(w, conn, 3, now=t + timedelta(seconds=20))
    assert abs((caught.value.retry_at - (t + timedelta(minutes=1))).total_seconds()) < 1
    assert len(w.fetcher.calls) == 2
    state, refusal = conn.execute(
        "SELECT state, refusal FROM ingest.lookup WHERE case_id = %s ORDER BY requested_at "
        "DESC LIMIT 1", (w.case_id,)).fetchone()
    assert (state, refusal) == ("REFUSED", "quota_exhausted")


def test_the_day_window_resets_at_the_utc_boundary(conn):
    from noctornal_api import lookups
    w = _world(conn, quota_per_minute=None, quota_per_day=1)
    evening = datetime(2026, 3, 10, 23, 59, 30, tzinfo=timezone.utc)
    assert _ask(w, conn, 1, now=evening)["status"] == 200
    with pytest.raises(lookups.QuotaExhausted) as caught:
        _ask(w, conn, 2, now=evening + timedelta(seconds=5))
    assert caught.value.retry_at == datetime(2026, 3, 11, tzinfo=timezone.utc)
    assert _ask(w, conn, 3, now=datetime(2026, 3, 11, 0, 0, 30,
                                         tzinfo=timezone.utc))["status"] == 200


def test_a_full_window_queues_a_none_lookup_when_asked(conn):
    w = _world(conn, quota_per_minute=1)
    _ask(w, conn, 1)
    got = _ask(w, conn, 2, queue_if_limited=True)
    assert got["status"] == 202 and got["not_before"] is not None
    state, not_before = conn.execute("SELECT state, not_before FROM ingest.lookup WHERE id = %s",
                                     (got["lookup_id"],)).fetchone()
    assert state == "QUEUED" and not_before == got["not_before"]
    assert len(w.fetcher.calls) == 1


def test_a_429_cools_the_provider_down_for_what_it_asked(conn):
    from noctornal_api import lookups
    w = _world(conn, http_error(429, retry_after=120))
    got = _ask(w, conn, 1)
    assert got["error_class"] == "rate_limited" and got["status"] == 502
    until, count = conn.execute("SELECT cooldown_until - now(), consecutive_429 FROM "
                                "ingest.provider WHERE id = %s", (w.provider.id,)).fetchone()
    assert 110 < until.total_seconds() <= 120 and count == 1
    with pytest.raises(lookups.CoolingDown):
        _ask(w, conn, 2)
    avail = w.service(conn).providers_for(w.case_id, user_id=w.analyst)[0]["availability"]
    assert avail["state"] == "COOLING_DOWN"


def test_a_429_without_retry_after_backs_off_and_is_capped(conn):
    w = _world(conn, http_error(429))
    conn.execute("UPDATE ingest.provider SET consecutive_429 = 9 WHERE id = %s",
                 (w.provider.id,))
    _ask(w, conn, 1)
    until = conn.execute("SELECT cooldown_until - now() FROM ingest.provider WHERE id = %s",
                         (w.provider.id,)).fetchone()[0]
    assert 3500 < until.total_seconds() <= 3600


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_key_locks_the_provider_and_the_detail_never_carries_it(conn, status):
    from noctornal_api import lookups
    w = _world(conn, http_error(status, f'{{"message": "bad key {KEY}"}}'))
    got = _ask(w, conn, 1)
    assert got["error_class"] == "credential_refused" and KEY not in got["detail"]
    status_now, reason = conn.execute("SELECT status, locked_reason FROM ingest.provider "
                                      "WHERE id = %s", (w.provider.id,)).fetchone()
    assert status_now == "LOCKED" and f"HTTP {status}" in reason
    stored = conn.execute("SELECT error_detail FROM ingest.lookup WHERE id = %s",
                          (got["lookup_id"],)).fetchone()[0]
    assert KEY not in stored
    with pytest.raises(lookups.LookupRefused) as caught:
        _ask(w, conn, 2)
    assert caught.value.code == "provider_locked"


def test_a_failed_send_still_counts(conn):
    from noctornal_api import lookups
    w = _world(conn, http_error(503), quota_per_minute=1)
    assert _ask(w, conn, 1)["error_class"] == "provider_error"
    with pytest.raises(lookups.QuotaExhausted):
        _ask(w, conn, 2)


def test_attempts_are_append_only(conn):
    import psycopg
    w = _world(conn)
    _ask(w, conn, 1)
    for sql in ("UPDATE ingest.lookup_attempt SET interactive = false WHERE provider_id = %s",
                "DELETE FROM ingest.lookup_attempt WHERE provider_id = %s"):
        with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
            conn.execute(sql, (w.provider.id,))


def test_a_reservation_waits_on_the_provider_row(conn):
    import psycopg
    from noctornal_api import lookups
    from noctornal_api.db import connect
    w = _world(conn)
    svc = w.service(conn)
    subject = svc.resolve_subject(w.case_id, {"kind": "VALUE", "selector_type": "DOMAIN",
                                              "value": "held.example.org"},
                                  user_id=w.analyst)
    fp = lookups.query_fingerprint(subject.selector_type, subject.value)
    lookup_id = svc._insert(subject, w.provider, "attribute_search", fp, user_id=w.analyst,
                            state="QUEUED", exposure_confirmed=True)
    other = connect()
    try:
        with conn.transaction():
            conn.execute("SELECT 1 FROM ingest.provider WHERE id = %s FOR UPDATE",
                         (w.provider.id,))
            with pytest.raises(psycopg.errors.LockNotAvailable), other.transaction():
                other.execute("SET LOCAL lock_timeout = '200ms'")
                lookups.LookupService(other)._reserve(lookup_id, interactive=True,
                                                      actor_id=w.analyst)
    finally:
        other.close()
