"""The pgp_key_directory readiness row (F10c, comms, 2026-09-24): off is a
pass; half configured is a fail naming the fix; on is a pass whose caveat
says what a lookup discloses and to whom. Whether the network boundary is
in force is egress_boundary's row. Pure: the route is a fake.
"""
from __future__ import annotations

import pytest

from noctornal_api import pgp_keys, readiness
from noctornal_api.egress import RouteUnavailable
from noctornal_api.egress_policy import EgressRoute, RoutePolicy, parse_rule


def _route(*rules, any_public=False):
    return EgressRoute.direct("integration", "wkd", RoutePolicy(
        "integration", tuple(parse_rule(r) for r in rules),
        any_public=any_public, admission="local"))


@pytest.fixture
def setup(monkeypatch):
    def use(ceiling=None, route=None):
        if ceiling is None:
            monkeypatch.delenv(pgp_keys.WKD_CEILING_ENV, raising=False)
        else:
            monkeypatch.setenv(pgp_keys.WKD_CEILING_ENV, ceiling)

        def fake(conn, declared=()):
            if route is None:
                raise RouteUnavailable("nothing named", code="route_unknown")
            return route
        monkeypatch.setattr(pgp_keys, "_wkd_route", fake)
    return use


def test_off_passes(setup):
    setup()
    check = readiness._pgp_key_directory(None)
    assert check.ok and check.evidence.startswith("off:")


def test_a_route_without_a_ceiling_fails(setup):
    setup(route=_route("openpgpkey.shop.net:443"))
    check = readiness._pgp_key_directory(None)
    assert not check.ok and "set NOCTORNAL_WKD_CEILING" in check.action


def test_a_ceiling_without_a_route_fails_naming_the_route(setup):
    setup("GREEN")
    check = readiness._pgp_key_directory(None)
    assert not check.ok
    assert "integration route named wkd" in check.action
    assert "<domain>:443 alone" in check.action


def test_a_bad_ceiling_fails(setup):
    setup("RED", _route("shop.net:443"))
    check = readiness._pgp_key_directory(None)
    assert not check.ok and "CLEAR, GREEN or AMBER" in check.action


def test_a_route_with_no_directory_or_a_wildcard_fails(setup):
    setup("GREEN", _route("shop.net:8443"))
    assert readiness._pgp_key_directory(None).evidence == pgp_keys.NO_DIRECTORY
    setup("GREEN", _route("shop.net:443", any_public=True))
    check = readiness._pgp_key_directory(None)
    assert not check.ok and check.evidence == pgp_keys.WILDCARD


def test_on_passes_with_the_exposure_said_out_loud(setup):
    setup("AMBER", _route("openpgpkey.shop.net:443", "mail.net:443"))
    check = readiness._pgp_key_directory(None)
    assert check.ok and "TLP:AMBER" in check.evidence
    assert "mail.net, shop.net" in check.caveat
    assert "second person" in check.caveat
    assert "which address was looked up" in check.caveat


def test_the_row_is_registered_and_not_blocking():
    assert "pgp_key_directory" in readiness.CHECK_NAMES
    assert "pgp_key_directory" not in readiness.BLOCKING_CHECKS
