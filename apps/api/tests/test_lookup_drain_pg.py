"""The lookup drain (F15.4, 2026-09-24): housekeeping
whatever the host switch says, then the queued NONE lookups only, paced by
the provider's queued share, each re-checked at send time; and the cron
entry scripts/lookup_drain.py with its exit codes.

The fetcher and the routes are fakes; nothing reaches a provider. **The
email prefix is `lkdrain-`.** Env-gated on DATABASE_URL.
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
    route_for_factory,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lkdrain-"
SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "lookup_drain.py"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _queued(conn, n=3, *, answer=None, **kw):
    """A NONE provider and `n` queued lookups from one batch."""
    w = lookup_world(conn, PREFIX, level="NONE", adapter="misp_rest",
                     fetcher=FakeFetcher(answer or fetched(200, MISP_GREEN_BODY)), **kw)
    ids = [make_selector(conn, w.case_id, "DOMAIN", f"d{i}.example.org") for i in range(n)]
    svc = w.service(conn)
    selection = {"selector_ids": [str(i) for i in ids]}
    plan = svc.plan(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                    operation="attribute_search", selection=selection)
    svc.commit_batch(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                     operation="attribute_search", selection=selection,
                     confirm_exposure="NONE", note="Enrich the list we were given.",
                     plan_digest=plan["plan_digest"])
    return w


def _states(conn, w):
    rows = conn.execute("SELECT state, count(*) FROM ingest.lookup WHERE case_id = %s "
                        "GROUP BY 1", (w.case_id,)).fetchall()
    return dict(rows)


def _script():
    spec = importlib.util.spec_from_file_location("lookup_drain_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_drain_sends_what_is_queued(conn):
    from noctornal_api import lookups
    w = _queued(conn)
    report = lookups.drain(conn, service=w.service(conn))
    assert report["providers"][w.provider.key]["answered"] == 3
    assert _states(conn, w) == {"ANSWERED": 3} and len(w.fetcher.calls) == 3
    actors = {r[0] for r in conn.execute(
        "SELECT actor_kind FROM audit.event WHERE case_id = %s AND action = 'LOOKUP_SENT'",
        (w.case_id,)).fetchall()}
    assert actors == {"SYSTEM"}


def test_the_drain_keeps_to_the_queued_share(conn):
    from noctornal_api import lookups
    w = _queued(conn, 6, quota_per_minute=5, reserve=20)
    report = lookups.drain(conn, service=w.service(conn))
    counts = report["providers"][w.provider.key]
    assert counts["answered"] == 4 and counts["deferred"] == 1
    assert _states(conn, w) == {"ANSWERED": 4, "QUEUED": 2}
    waiting = conn.execute("SELECT count(*) FROM ingest.lookup WHERE case_id = %s AND "
                           "state = 'QUEUED' AND not_before > now()",
                           (w.case_id,)).fetchone()[0]
    assert waiting == 2


def test_the_drain_rechecks_the_requester_at_send_time(conn):
    from noctornal_api import lookups
    w = _queued(conn)
    conn.execute("DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                 (w.case_id, w.analyst))
    lookups.drain(conn, service=w.service(conn))
    assert _states(conn, w) == {"REFUSED": 3} and not w.fetcher.calls
    refusals = {r[0] for r in conn.execute("SELECT refusal FROM ingest.lookup WHERE case_id "
                                           "= %s", (w.case_id,)).fetchall()}
    assert refusals == {"requester_withdrawn"}


def test_the_drain_refuses_what_the_provider_now_exposes_differently(conn):
    from noctornal_api import lookups, providers
    w = _queued(conn)
    reg = providers.ProviderRegistry(conn, route_for=w.route_for)
    reg.update(w.provider.id, {"exposure_level": "VENDOR",
                               "exposure_basis": "It moved to the vendor's cloud."},
               actor_id=w.admin)
    reg.enable(w.provider.id, confirm_exposure="VENDOR", actor_id=w.admin)
    lookups.drain(conn, service=w.service(conn))
    assert _states(conn, w) == {"REFUSED": 3} and not w.fetcher.calls


def test_a_provider_with_no_route_is_reported_and_sends_nothing(conn):
    from noctornal_api import lookups
    w = _queued(conn)
    report = lookups.drain(conn, service=w.service(conn, route_for=route_for_factory({})))
    assert report["no_route"] and report["no_route"][0].startswith(w.provider.key)
    assert _states(conn, w) == {"QUEUED": 3} and not w.fetcher.calls


def test_a_failed_drained_send_backs_off_and_gives_up_after_three(conn):
    from noctornal_api import lookups
    from noctornal_api.pinned_http import Unreachable
    w = _queued(conn, 1, answer=Unreachable("no answer from the host"))
    lookups.drain(conn, service=w.service(conn))
    state, attempts, not_before = conn.execute(
        "SELECT state, attempts, not_before > now() FROM ingest.lookup WHERE case_id = %s",
        (w.case_id,)).fetchone()
    assert (state, attempts, not_before) == ("QUEUED", 1, True)
    for _ in range(2):
        conn.execute("UPDATE ingest.lookup SET not_before = now() - interval '1 second' "
                     "WHERE case_id = %s", (w.case_id,))
        lookups.drain(conn, service=w.service(conn))
    assert conn.execute("SELECT state, attempts FROM ingest.lookup WHERE case_id = %s",
                        (w.case_id,)).fetchone() == ("FAILED", 3)


def test_the_drain_stops_at_its_limit_and_its_time(conn):
    from noctornal_api import lookups
    w = _queued(conn, 3)
    report = lookups.drain(conn, service=w.service(conn), limit=1)
    assert report["providers"][w.provider.key]["answered"] == 1
    # Two left: the clock reads 0 at the start and for the first, then past
    # the budget for the second.
    ticks = iter([0.0, 0.0, 999.0, 999.0])
    report = lookups.drain(conn, service=w.service(conn), clock=lambda: next(ticks),
                           max_seconds=10)
    assert report["providers"][w.provider.key]["deferred"] == 1
    assert _states(conn, w) == {"ANSWERED": 2, "QUEUED": 1}


def test_a_dry_run_writes_and_sends_nothing(conn):
    from noctornal_api import lookups
    w = _queued(conn)
    report = lookups.drain(conn, service=w.service(conn), dry_run=True)
    assert report["providers"][w.provider.key]["sent"] == 3
    assert _states(conn, w) == {"QUEUED": 3} and not w.fetcher.calls


def test_a_provider_another_drain_holds_is_skipped(conn):
    from noctornal_api import lookups
    from noctornal_api.db import connect
    w = _queued(conn)
    other = connect()
    try:
        other.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))",
                      (lookups._drain_lock(w.provider.id),))
        report = lookups.drain(conn, service=w.service(conn))
        assert report["providers"][w.provider.key]["skipped"] == 1
        assert not w.fetcher.calls
    finally:
        other.close()


def test_housekeeping_runs_with_the_switch_off(conn, monkeypatch):
    from noctornal_api import lookups
    w = lookup_world(conn, PREFIX, fetcher=FakeFetcher(fetched(200, b"{}")))
    waiting = w.service(conn).request(
        w.case_id, {"kind": "VALUE", "selector_type": "DOMAIN", "value": "example.org"},
        provider_id=w.provider.id, operation="domain_report", user_id=w.analyst,
        confirm_exposure="VENDOR", authorised_by=w.owner, authorisation_note="needed")
    with conn.transaction():
        conn.execute("ALTER TABLE ingest.lookup DISABLE TRIGGER USER")
        conn.execute("UPDATE ingest.lookup SET requested_at = now() - interval '25 hours', "
                     "signoff_expires_at = now() - interval '1 hour' WHERE id = %s",
                     (waiting["lookup_id"],))
        conn.execute("ALTER TABLE ingest.lookup ENABLE TRIGGER USER")
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "off")
    done = lookups.housekeeping(conn)
    assert done["expired"] >= 1
    assert conn.execute("SELECT state FROM ingest.lookup WHERE id = %s",
                        (waiting["lookup_id"],)).fetchone()[0] == "EXPIRED"
    actor = conn.execute("SELECT actor_kind, detail->>'requested_by' FROM audit.event "
                         "WHERE object_id = %s AND action = 'LOOKUP_SIGNOFF_EXPIRED'",
                         (waiting["lookup_id"],)).fetchone()
    assert actor == ("SYSTEM", str(w.analyst))


def test_housekeeping_fails_a_send_whose_process_ended(conn):
    from noctornal_api import lookups
    w = _queued(conn, 1)
    lookup_id = conn.execute("SELECT id FROM ingest.lookup WHERE case_id = %s",
                             (w.case_id,)).fetchone()[0]
    with conn.transaction():
        w.service(conn)._reserve(lookup_id, interactive=False, actor_id=None)
    with conn.transaction():
        conn.execute("ALTER TABLE ingest.lookup_attempt DISABLE TRIGGER USER")
        conn.execute("UPDATE ingest.lookup_attempt SET sent_at = now() - interval '1 hour' "
                     "WHERE lookup_id = %s", (lookup_id,))
        conn.execute("ALTER TABLE ingest.lookup_attempt ENABLE TRIGGER USER")
    assert lookups.housekeeping(conn)["abandoned"] >= 1
    assert conn.execute("SELECT state, error_class FROM ingest.lookup WHERE id = %s",
                        (lookup_id,)).fetchone() == ("FAILED", "abandoned")


def test_the_script_prints_the_switch_first_and_exits_zero_when_off(conn, monkeypatch,
                                                                    capsys):
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "off")
    assert _script().main([], conn=conn) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "NOCTORNAL_OUTBOUND_LOOKUPS=off"
    assert out[1].startswith("housekeeping ") and "off on this host" in out[2]


def test_the_script_exits_one_when_a_send_failed(conn, capsys):
    from noctornal_api.pinned_http import Unreachable
    w = _queued(conn, 1, answer=Unreachable("down"))
    # The third attempt fails for good, so the pass reports a failure.
    with conn.transaction():
        conn.execute("ALTER TABLE ingest.lookup DISABLE TRIGGER USER")
        conn.execute("UPDATE ingest.lookup SET attempts = 2, sent_at = now() - "
                     "interval '1 hour' WHERE case_id = %s", (w.case_id,))
        conn.execute("ALTER TABLE ingest.lookup ENABLE TRIGGER USER")
    assert _script().main([], conn=conn, service=w.service(conn)) == 1
    assert f"{w.provider.key} " in capsys.readouterr().out


def test_the_script_refuses_published_credentials_in_production(monkeypatch, capsys):
    from noctornal_api import config
    monkeypatch.setenv(config.ENV_VAR, config.PRODUCTION)
    monkeypatch.setattr(config, "published_credentials",
                        lambda: [type("P", (), {"variable": "NOCTORNAL_TOTP_KEK"})()])
    assert _script().main([]) == 2
    assert "NOCTORNAL_TOTP_KEK" in capsys.readouterr().out
