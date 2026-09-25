"""The readiness row outbound_lookup_providers (F15.2, 2026-09-24): the
host switch as read, and every enabled provider's key, route, rotation
date and adapter.

Routes are fakes; nothing reaches a provider. **The email prefix is
`rdprov-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import pytest

from outbound_support import (
    DATABASE_URL,
    make_provider,
    make_user,
    route_for_factory,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "rdprov-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _provider(conn, **kw):
    a, _ = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    b, _ = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    return make_provider(conn, a, b, **kw)


def _verdict(conn, rf=None):
    from noctornal_api import providers
    return providers.readiness_verdict(conn, route_for=rf)


def test_the_row_is_registered_and_readable_on_its_own(conn):
    from noctornal_api import readiness
    assert "outbound_lookup_providers" in readiness.CHECK_NAMES
    assert readiness.check("outbound_lookup_providers", conn).check == \
        "outbound_lookup_providers"


def test_switch_off_passes_and_says_nothing_is_sent(conn, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "off")
    ok, evidence, _action, _caveat = _verdict(conn)
    assert ok and evidence.startswith("Outbound lookups are off on this host")


def test_switch_off_with_an_enabled_provider_is_a_caveat(conn, monkeypatch):
    _provider(conn)
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "off")
    ok, _evidence, _action, caveat = _verdict(conn)
    assert ok and "enabled in Administration but the host switch is off" in caveat


def test_a_switch_that_is_neither_on_nor_off_fails(conn, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "yes")
    ok, evidence, action, _caveat = _verdict(conn)
    assert not ok and '"yes"' in evidence and "set it to on or off" in action


def test_an_enabled_provider_is_listed_with_its_exposure_quota_and_route(conn):
    p, rf = _provider(conn)
    ok, evidence, _action, caveat = _verdict(conn, rf)
    assert ok, evidence
    assert f"{p.key}: VENDOR, ceiling GREEN, 60 per minute, route {p.egress_route} (direct)" \
        in evidence
    assert f"{p.key} is not yet verified against the live service" in caveat


def test_an_enabled_provider_with_no_route_fails(conn):
    p, _rf = _provider(conn)
    ok, evidence, _action, _caveat = _verdict(conn, route_for_factory({}))
    assert not ok and f"{p.key} is enabled with no route out" in evidence


@pytest.mark.parametrize("fault,words", [
    ("locked", "is locked"),
    ("rotation", "past its key rotation date"),
    ("adapter", "adapter changed in this build"),
    ("origin", "key entered for another host"),
])
def test_each_fault_of_an_enabled_provider_fails_the_row(conn, fault, words):
    p, rf = _provider(conn)
    sql = {"locked": "UPDATE ingest.provider SET status = 'LOCKED', locked_reason = "
                     "'the provider refused the stored key' WHERE id = %s",
           "rotation": "UPDATE ingest.provider SET rotate_by = current_date - 1 WHERE id = %s",
           "adapter": "UPDATE ingest.provider SET adapter_version = '0' WHERE id = %s",
           "origin": "UPDATE ingest.provider SET secret_origin = 'https://elsewhere:443' "
                     "WHERE id = %s"}[fault]
    conn.execute(sql, (p.id,))
    ok, evidence, _action, _caveat = _verdict(conn, rf)
    assert not ok and f"{p.key}" in evidence and words in evidence


def test_a_missing_pepper_fails_the_row(conn, monkeypatch):
    _p, rf = _provider(conn)
    monkeypatch.setenv("NOCTORNAL_INGEST_PEPPER", "")
    ok, evidence, _action, _caveat = _verdict(conn, rf)
    assert not ok and "NOCTORNAL_INGEST_PEPPER is unset" in evidence


def test_a_public_provider_is_a_caveat(conn):
    p, rf = _provider(conn, level="PUBLIC", adapter="shodan_host")
    ok, _evidence, _action, caveat = _verdict(conn, rf)
    assert ok and f"{p.key} is PUBLIC" in caveat
