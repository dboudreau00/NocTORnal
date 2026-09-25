"""Web Key Directory lookups, the pure parts (F10c, comms, 2026-09-24).

No network: a fake route and a fake fetcher. What holds: only the hash
leaves (no ?l=); an address that is never a public directory is refused;
the directories come from the wkd route's allowlist and a wildcard turns
lookups off; the fallback to the direct method happens only when the
advanced host's name does not exist; no redirect is followed and no
User-Agent is sent; every policy problem fails closed.
"""
from __future__ import annotations

import pytest

from noctornal_api import pgp_keys
from noctornal_api.egress_policy import EgressRoute, RoutePolicy, Rule
from noctornal_api.pgp import PgpError
from noctornal_api.pgp_keys import (
    ADVANCED,
    DIRECT,
    PgpLookupService,
    _directories,
    directory_policy,
    parse_address,
    wkd_hash,
    wkd_urls,
)
from noctornal_api.pinned_http import (
    CollectionError,
    HttpStatusError,
    UnresolvableHost,
)


def route(*rules: str, any_public=False) -> EgressRoute:
    from noctornal_api.egress_policy import parse_rule
    policy = RoutePolicy("integration", tuple(parse_rule(r) for r in rules),
                         any_public=any_public, admission="local")
    return EgressRoute.direct("integration", "wkd", policy)


def test_the_hash_is_the_draft_vector_and_only_the_hash_leaves():
    assert wkd_hash("Joe.Doe") == "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
    urls = wkd_urls("example.org", wkd_hash("Joe.Doe"))
    assert urls[ADVANCED] == ("https://openpgpkey.example.org/.well-known/"
                              "openpgpkey/example.org/hu/"
                              "iy9q119eutrkn8s1mk4r39qejnbu3n5q")
    assert urls[DIRECT] == ("https://example.org/.well-known/openpgpkey/hu/"
                            "iy9q119eutrkn8s1mk4r39qejnbu3n5q")
    assert not any("l=" in u or "?" in u for u in urls.values())


def test_an_idna_domain_goes_out_as_ascii():
    local, domain = parse_address("Joe.Doe@bücher.net")
    assert domain == "xn--bcher-kva.net"
    assert all(u.isascii() for u in wkd_urls(domain, wkd_hash(local)).values())


@pytest.mark.parametrize("address", [
    "vendor@192.0.2.1", "vendor@[192.0.2.1]", "vendor@shop.onion",
    "vendor@shop.test", "vendor@localhost", "vendor@example",
    "two@at@shop.net", "x" * 65 + "@shop.net", "ven dor@shop.net",
    "ven\u0000dor@shop.net", "@shop.net", "vendor@", "vendor@shop.example",
    "vendor@-bad-.net",
])
def test_addresses_that_are_never_a_public_directory(address):
    with pytest.raises(PgpError):
        parse_address(address)


def test_the_directories_come_from_the_route():
    found, wildcard = _directories(route("openpgpkey.shop.net:443",
                                         "mail.net:443", "other.net:8443"))
    assert not wildcard
    assert dict(found) == {"shop.net": (ADVANCED,), "mail.net": (DIRECT,)}
    both, _ = _directories(route("openpgpkey.both.net:443", "both.net:443"))
    assert dict(both) == {"both.net": (ADVANCED, DIRECT)}


def test_a_wildcard_route_turns_lookups_off():
    """A route that reaches any public name would
    reopen lookups to a domain the people under investigation run."""
    assert _directories(route("shop.net:443", any_public=True)) == ((), True)
    suffix = EgressRoute.direct(
        "integration", "wkd",
        RoutePolicy("integration", (Rule(frozenset({443}), suffix="shop.net"),),
                    any_public=False, admission="local"))
    assert _directories(suffix) == ((), True)


# ---------------------------------------------------------------------------
# The policy fails closed
# ---------------------------------------------------------------------------

@pytest.fixture
def env(monkeypatch):
    monkeypatch.delenv(pgp_keys.WKD_CEILING_ENV, raising=False)

    def use(ceiling=None, the_route=None, raises=None):
        if ceiling is None:
            monkeypatch.delenv(pgp_keys.WKD_CEILING_ENV, raising=False)
        else:
            monkeypatch.setenv(pgp_keys.WKD_CEILING_ENV, ceiling)

        def fake(conn, declared=()):
            if raises is not None:
                raise raises
            return the_route
        monkeypatch.setattr(pgp_keys, "_wkd_route", fake)
    return use


def test_every_policy_problem_fails_closed(env):
    from noctornal_api.egress import RouteUnavailable
    env()
    assert directory_policy(None).problem == pgp_keys.OFF_PROBLEM
    for bad in ("AMBER_STRICT", "RED", "PURPLE"):
        env(bad, route("shop.net:443"))
        policy = directory_policy(None)
        assert not policy.enabled and policy.problem == pgp_keys.BAD_CEILING
    env("GREEN", raises=RouteUnavailable("no route", code="route_unknown"))
    assert directory_policy(None).problem == pgp_keys.NO_ROUTE
    env("GREEN", route("shop.net:443", any_public=True))
    assert directory_policy(None).problem == pgp_keys.WILDCARD
    env("GREEN", route("shop.net:8443"))
    assert directory_policy(None).problem == pgp_keys.NO_DIRECTORY
    env("green", route("openpgpkey.shop.net:443"))
    policy = directory_policy(None)
    assert policy.enabled and policy.ceiling == "GREEN"
    assert policy.directories == (("shop.net", (ADVANCED,)),)


def test_no_usable_gpg_turns_lookups_off(env, monkeypatch):
    """A key found could not be read after the address was disclosed."""
    env("GREEN", route("shop.net:443"))
    monkeypatch.setenv("NOCTORNAL_GPG", "/nonexistent/gpg-binary")
    assert directory_policy(None).problem == pgp_keys.NO_GPG


# ---------------------------------------------------------------------------
# Sending: one client call, the fallback, the outcomes
# ---------------------------------------------------------------------------

class _Fetched:
    def __init__(self, status, body=b""):
        self.status, self.body = status, body


def _planned(domain="shop.net"):
    urls = wkd_urls(domain, wkd_hash("vendor"))
    return [(ADVANCED, urls[ADVANCED]), (DIRECT, urls[DIRECT])]


def _send(fetch, planned=None):
    return PgpLookupService._send(planned or _planned(), route("shop.net:443"),
                                  fetch)


def test_the_fallback_is_only_for_a_name_that_does_not_exist():
    seen = []

    def fetch(url, *, route):
        seen.append(url)
        if url.startswith("https://openpgpkey."):
            raise UnresolvableHost("openpgpkey.shop.net", permanent=True)
        return _Fetched(200, b"key")

    out = _send(fetch)
    assert out["state"] == "FOUND" and out["method_used"] == DIRECT
    assert len(seen) == 2


@pytest.mark.parametrize("failure", [
    UnresolvableHost("openpgpkey.shop.net", permanent=False),
    HttpStatusError(503, retry_after=None, excerpt="", location=None,
                    location_host=None, headers=None),
    CollectionError("reset"),
], ids=["temporary", "5xx", "other"])
def test_no_fallback_on_anything_else(failure):
    seen = []

    def fetch(url, *, route):
        seen.append(url)
        raise failure

    out = _send(fetch)
    assert out["state"] == "FAILED" and len(seen) == 1


def test_a_404_on_the_advanced_method_is_final():
    seen = []

    def fetch(url, *, route):
        seen.append(url)
        return _Fetched(404)

    out = _send(fetch)
    assert out["state"] == "NOT_FOUND" and len(seen) == 1


def test_a_redirect_is_failed_and_never_followed():
    def fetch(url, *, route):
        raise HttpStatusError(302, retry_after=None, excerpt="", location="x",
                              location_host="elsewhere.net", headers=None)

    out = _send(fetch)
    assert out["state"] == "FAILED"
    assert "follows none" in out["detail"]
    assert "elsewhere" not in out["detail"]


def test_the_client_call_sends_no_user_agent_and_follows_nothing(monkeypatch):
    from noctornal_api import pinned_http
    calls = []

    def fake(url, **kw):
        calls.append(kw)
        return _Fetched(404)

    monkeypatch.setattr(pinned_http, "fetch_response", fake)
    the_route = route("openpgpkey.shop.net:443")
    pgp_keys._default_fetcher(_planned()[0][1], route=the_route)
    (kw,) = calls
    assert kw["route"] is the_route
    assert kw["user_agent"] is None and kw["max_redirects"] == 0
    assert kw["accept_status"] == frozenset({404})
    assert kw["max_bytes"] == pgp_keys.MAX_KEY_BYTES
    assert kw["deadline"] == 20.0 and kw["method"] == "GET"


def test_an_exception_text_is_never_the_detail():
    def fetch(url, *, route):
        raise CollectionError("secret-token=abcdef123456 at 10.0.0.9")

    out = _send(fetch)
    assert "10.0.0.9" not in out["detail"] and "secret" not in out["detail"]


# ---------------------------------------------------------------------------
# The shared registries the key directory lookups add to (egress.py)
# ---------------------------------------------------------------------------

def test_the_key_directory_gate_needs_a_ceiling_and_keeps_the_floor():
    from noctornal_api.egress import (
        DENY_ABOVE_DESTINATION_CEILING,
        DENY_NO_CEILING,
        Destination,
        can_egress,
    )
    assert can_egress("GREEN", Destination.KEY_DIRECTORY).reason == DENY_NO_CEILING
    assert can_egress("GREEN", Destination.KEY_DIRECTORY,
                      destination_ceiling="GREEN").allowed
    assert can_egress("AMBER", Destination.KEY_DIRECTORY,
                      destination_ceiling="GREEN").reason == \
        DENY_ABOVE_DESTINATION_CEILING
    assert can_egress("RED", Destination.KEY_DIRECTORY,
                      destination_ceiling="AMBER").denied


def test_wkd_is_a_registered_integration_route(monkeypatch):
    """In development with no provider, a declared rule is the route's
    whole allowlist; the lookup always declares the directory's names."""
    import sys

    from noctornal_api import egress
    from noctornal_api.egress_policy import Rule
    monkeypatch.setitem(sys.modules, egress.ROUTE_PROVIDER_MODULE, None)
    egress._reset_route_provider()
    for name in ("NOCTORNAL_ENV", egress.PROXY_URL_ENV):
        monkeypatch.delenv(name, raising=False)
    try:
        the_route = egress.route_for(
            "integration", "wkd", conn=object(),
            declared=(Rule.for_host("openpgpkey.shop.net", {443}),))
        assert the_route.permits("openpgpkey.shop.net", 443)
        assert not the_route.permits("elsewhere.net", 443)
        # Nothing declared and no administrator route: no route, so the
        # directory policy reads lookups as off.
        with pytest.raises(egress.RouteUnavailable):
            egress.route_for("integration", "wkd", conn=object())
    finally:
        egress._reset_route_provider()


def test_a_ceiling_is_an_outbound_use_for_the_start_refusal(monkeypatch):
    """Production refuses to start with outbound uses and no proxy (docs/00
    decision 68); a lookup ceiling is one."""
    from noctornal_api import egress
    uses = dict(egress.OUTBOUND_USES)
    monkeypatch.delenv(pgp_keys.WKD_CEILING_ENV, raising=False)
    assert uses["wkd"](None) is None
    monkeypatch.setenv(pgp_keys.WKD_CEILING_ENV, "GREEN")
    assert "Web Key Directories" in uses["wkd"](None)
