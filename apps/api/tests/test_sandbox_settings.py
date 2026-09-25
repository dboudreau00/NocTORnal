"""The sandbox settings reader and its production refusals (F14,
2026-09-24). Pure.

Unset means off with no problem; the exposure and the ceiling are the
operator's declarations with no default; AMBER_STRICT and RED are refused
as ceilings; network routes and machines are classed; the default route
must be offered; a private sandbox address needs its network; production
refuses http, credentials in the URL, a missing token, an undeclared
exposure or ceiling, a bad route list, and a sandbox with no egress proxy,
naming variables and never values; there is no raw-submission setting.
"""
from __future__ import annotations

import pytest

from noctornal_api import sandbox

BASE = {"NOCTORNAL_SANDBOX_PROVIDER": "capev2",
        "NOCTORNAL_SANDBOX_URL": "https://cape.lab.example:8000",
        "NOCTORNAL_SANDBOX_TOKEN": "tok-secret-value-1234",
        "NOCTORNAL_SANDBOX_EXPOSURE": "NONE",
        "NOCTORNAL_SANDBOX_CEILING": "GREEN"}


def _with(**changes):
    env = dict(BASE)
    for key, value in changes.items():
        name = "NOCTORNAL_SANDBOX_" + key
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def test_unset_means_off_with_no_problem():
    assert sandbox.sandbox_settings({}) == (None, None)


def test_a_complete_configuration_reads():
    settings, problem = sandbox.sandbox_settings(BASE)
    assert problem is None
    assert settings.api_base == "https://cape.lab.example:8000/apiv2"
    assert settings.target_host == "cape.lab.example:8000"
    assert settings.routes == (("none", "ISOLATED"),)
    assert "tok-secret" not in repr(settings)


@pytest.mark.parametrize("missing", ["EXPOSURE", "CEILING", "TOKEN"])
def test_the_declarations_and_the_token_are_required(missing):
    _settings, problem = sandbox.sandbox_settings(_with(**{missing: None}))
    assert problem and f"NOCTORNAL_SANDBOX_{missing}" in problem


@pytest.mark.parametrize("ceiling", ["AMBER_STRICT", "RED", "PURPLE"])
def test_a_ceiling_above_amber_is_refused(ceiling):
    _settings, problem = sandbox.sandbox_settings(_with(CEILING=ceiling))
    assert problem and "CEILING" in problem


def test_network_routes_are_classed():
    for route in ("none", "drop", "inetsim"):
        assert sandbox.network_route_class(route) == "ISOLATED"
    for route in ("internet", "tor", "vpn0", "socks"):
        assert sandbox.network_route_class(route) == "LIVE"
    settings, _p = sandbox.sandbox_settings(
        _with(NETWORK_ROUTES="none,internet,tor"))
    assert settings.route_classes == {"none": "ISOLATED", "internet": "LIVE",
                                      "tor": "LIVE"}


def test_the_default_route_must_be_offered():
    _s, problem = sandbox.sandbox_settings(
        _with(NETWORK_ROUTES="internet", DEFAULT_NETWORK_ROUTE="none"))
    assert problem and "DEFAULT_NETWORK_ROUTE" in problem


def test_machines_are_classed_and_a_bad_list_is_refused():
    settings, _p = sandbox.sandbox_settings(
        _with(MACHINES="win10:ISOLATED,bridged:LIVE"))
    assert settings.machine_classes == {"win10": "ISOLATED", "bridged": "LIVE"}
    _s, problem = sandbox.sandbox_settings(_with(MACHINES="win10"))
    assert problem and "MACHINES" in problem


def test_a_private_sandbox_address_needs_its_network():
    _s, problem = sandbox.sandbox_settings(_with(URL="https://10.20.0.5:8000"))
    assert problem and "NOCTORNAL_SANDBOX_NETWORK" in problem
    settings, problem = sandbox.sandbox_settings(
        _with(URL="https://10.20.0.5:8000", NETWORK="10.20.0.0/24"))
    assert problem is None and str(settings.network) == "10.20.0.0/24"


@pytest.mark.parametrize("url", ["http://cape.example:8000",
                                 "https://zqxuser:zqxsecret@cape.example",
                                 "https://cape.example/?x=1", "cape.example"])
def test_a_url_that_is_not_plain_https_is_refused(url):
    _s, problem = sandbox.sandbox_settings(_with(URL=url))
    assert problem and "NOCTORNAL_SANDBOX_URL" in problem
    assert "zqx" not in problem


def test_there_is_no_raw_submission_setting():
    assert not any("RAW" in name or "SUBMIT_AS" in name for name in sandbox.ALL_ENV)


def _production(**extra):
    env = {"NOCTORNAL_ENV": "production", **BASE, **extra}
    return sandbox.production_problems(env)


def test_production_refuses_a_sandbox_with_no_egress_proxy():
    problems = _production()
    assert any("NOCTORNAL_EGRESS_PROXY_URL" in p for p in problems)
    assert not any("tok-secret" in p or "cape.lab.example" in p for p in problems)
    assert not any("NOCTORNAL_EGRESS_PROXY_URL is not" in p
                   for p in _production(NOCTORNAL_EGRESS_PROXY_URL="http://egress:3128"))


def test_production_refuses_unusable_settings_naming_the_variable():
    problems = sandbox.production_problems(
        {"NOCTORNAL_ENV": "production", **_with(EXPOSURE=None)})
    assert problems and "NOCTORNAL_SANDBOX_EXPOSURE" in problems[0]
    problems = sandbox.production_problems(
        {"NOCTORNAL_ENV": "production", **_with(NETWORK_ROUTES="none,,bad name")})
    assert problems and "NETWORK_ROUTES" in problems[0]


def test_config_carries_the_sandbox_refusals():
    from noctornal_api.config import verify_environment
    problems = verify_environment({"NOCTORNAL_ENV": "production",
                                   **_with(TOKEN=None)})
    assert any("NOCTORNAL_SANDBOX_TOKEN" in p for p in problems)


def test_config_refuses_the_hash_set_authority_placeholder():
    from noctornal_api.config import verify_environment
    problems = verify_environment({"NOCTORNAL_ENV": "production",
                                   "NOCTORNAL_HASH_SET_AUTHORITY": "replace-me"})
    assert any("NOCTORNAL_HASH_SET_AUTHORITY" in p for p in problems)
    problems = verify_environment({"NOCTORNAL_ENV": "production",
                                   "NOCTORNAL_MAX_SCREENING_LIST_BYTES": "lots"})
    assert any("NOCTORNAL_MAX_SCREENING_LIST_BYTES" in p for p in problems)
