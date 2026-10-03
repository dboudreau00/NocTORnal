"""egress-lookup-signoff-exposure (review of 2026-10-03).

A lookup requested and confirmed at VENDOR, with a colleague named to sign
it off, was SENT at sign-off after an administrator raised its provider to
PUBLIC and enabled it again: the sign-off ran the gates and never compared
the provider's exposure with the one the lookup recorded. The drain refuses
the same row (`exposure_changed`); raising the exposure also withdrew
nothing, while lowering it cancels the waiting sign-offs.

These fail on dc28ffa: the fetcher is called once and the row ends
ANSWERED at VENDOR while the LOOKUP_SENT audit says PUBLIC.

The fetcher and the routes are fakes; nothing reaches a provider. Email
prefix `r46x-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from outbound_support import (
    DATABASE_URL,
    FakeFetcher,
    fetched,
    lookup_world,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46x-"
DOMAIN = {"kind": "VALUE", "selector_type": "DOMAIN", "value": "r46x-target.example",
          "classification": "CLEAR"}
VT_DOMAIN = (Path(__file__).parent / "fixtures" / "lookups"
             / "virustotal_domain_200.json").read_bytes()
BASIS = "The vendor now publishes every query it receives."


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _world(conn):
    w = lookup_world(conn, PREFIX, level="VENDOR", case_classification="CLEAR",
                     fetcher=FakeFetcher(fetched(200, VT_DOMAIN)))
    got = w.service(conn).request(
        w.case_id, DOMAIN, provider_id=w.provider.id, operation="domain_report",
        user_id=w.analyst, confirm_exposure="VENDOR", authorised_by=w.owner,
        authorisation_note="attribution check")
    assert got["status"] == 202
    return w, got["lookup_id"]


def _row(conn, lookup_id):
    return conn.execute("SELECT state, exposure_level, refusal FROM ingest.lookup "
                        "WHERE id = %s", (lookup_id,)).fetchone()


def _raise_to_public(conn, w):
    from noctornal_api import providers
    reg = providers.ProviderRegistry(conn, route_for=w.route_for)
    reg.update(w.provider.id, {"exposure_level": "PUBLIC", "exposure_basis": BASIS},
               actor_id=w.admin)
    return reg


def test_a_provider_raised_after_the_request_withdraws_the_waiting_sign_off(conn):
    w, lookup_id = _world(conn)
    _raise_to_public(conn, w)
    state, level, refusal = _row(conn, lookup_id)
    assert (state, level) == ("CANCELLED", "VENDOR")
    assert "exposure changed" in refusal
    detail = conn.execute(
        "SELECT detail FROM audit.event WHERE object_id = %s AND action = "
        "'PROVIDER_EXPOSURE_CHANGED'", (w.provider.id,)).fetchone()[0]
    assert detail["signoffs_cancelled"] == 1


def test_a_sign_off_is_refused_when_the_exposure_rose_whatever_re_enabled_it(conn):
    """The guard in sign_off itself, with the withdrawal out of the way: the
    provider is raised and enabled directly, as an administrator reaching it
    by any other route would leave it."""
    from noctornal_api.lookups import LookupRefused
    w, lookup_id = _world(conn)
    conn.execute("ALTER TABLE ingest.provider DISABLE TRIGGER USER")
    conn.execute("UPDATE ingest.provider SET exposure_level = 'PUBLIC', "
                 "classification_ceiling = 'CLEAR', enabled = true WHERE id = %s",
                 (w.provider.id,))
    conn.execute("ALTER TABLE ingest.provider ENABLE TRIGGER USER")
    with pytest.raises(LookupRefused) as refused:
        w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True,
                                 note="ok")
    assert refused.value.code == "exposure_changed"
    assert "PUBLIC" in refused.value.detail and "VENDOR" in refused.value.detail
    assert w.fetcher.calls == [], "the lookup was sent"
    state, level, refusal = _row(conn, lookup_id)
    assert (state, level, refusal) == ("REFUSED", "VENDOR", "exposure_changed")
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s "
                        "AND action = 'LOOKUP_SENT'", (lookup_id,)).fetchone()[0] == 0
    audit = conn.execute("SELECT detail->>'code' FROM audit.event WHERE object_id = %s "
                         "AND action = 'LOOKUP_REFUSED'", (lookup_id,)).fetchone()
    assert audit == ("exposure_changed",)


def test_the_named_person_still_signs_when_the_exposure_did_not_move(conn):
    """The legitimate path is unchanged: the same level, the same sign-off,
    one send."""
    w, lookup_id = _world(conn)
    out = w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True,
                                   note="ok")
    assert out["status"] == 200
    assert len(w.fetcher.calls) == 1
    assert _row(conn, lookup_id)[:2] == ("ANSWERED", "VENDOR")


def test_a_provider_whose_exposure_did_not_change_keeps_its_waiting_sign_offs(conn):
    """Only a change of exposure withdraws: renaming does not."""
    from noctornal_api import providers
    w, lookup_id = _world(conn)
    reg = providers.ProviderRegistry(conn, route_for=w.route_for)
    reg.update(w.provider.id, {"display_name": "Renamed by r46x"}, actor_id=w.admin)
    assert _row(conn, lookup_id)[0] == "AWAITING_SIGNOFF"
