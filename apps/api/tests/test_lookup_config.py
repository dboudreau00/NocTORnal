"""The settings the outbound integrations add (F7, F8 and F15.2,
2026-09-24): what production refuses to start
with, and the host switch that is the second act before any lookup
leaves. Pure: no database, no network.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from noctornal_api import config, providers

BASE = {config.ENV_VAR: config.PRODUCTION}


def _problems(**extra) -> list[str]:
    return config.verify_environment({**BASE, **extra})


def _says(problems: list[str], words: str) -> bool:
    return any(words in p for p in problems)


def test_lookups_on_without_a_proxy_is_refused_in_production():
    assert _says(_problems(NOCTORNAL_OUTBOUND_LOOKUPS="on"), "NOCTORNAL_OUTBOUND_LOOKUPS is on")
    assert not _says(_problems(NOCTORNAL_OUTBOUND_LOOKUPS="on",
                               NOCTORNAL_EGRESS_PROXY_URL="http://proxy.internal:3128"),
                     "NOCTORNAL_OUTBOUND_LOOKUPS is on")
    assert not _says(_problems(NOCTORNAL_OUTBOUND_LOOKUPS="off"),
                     "NOCTORNAL_OUTBOUND_LOOKUPS is on")


def test_an_http_webhook_is_refused_in_production():
    assert _says(_problems(NOCTORNAL_WEBHOOK_URL="http://hooks.example.org/x"),
                 "NOCTORNAL_WEBHOOK_URL is not an https address")
    assert not _says(_problems(NOCTORNAL_WEBHOOK_URL="https://hooks.example.org/x"),
                     "NOCTORNAL_WEBHOOK_URL")


@pytest.mark.parametrize("flag", ["NOCTORNAL_WEBHOOK_ALLOW_HTTP", "NOCTORNAL_JIRA_ALLOW_HTTP"])
def test_the_plain_http_flags_are_refused_in_production(flag):
    assert _says(_problems(**{flag: "1"}), f"{flag} is set")


@pytest.mark.parametrize("value,refused", [("RED", True), ("public", True), ("amber", False),
                                           ("GREEN", False)])
def test_the_jira_ceiling_is_a_label_jira_may_hold(value, refused):
    assert _says(_problems(NOCTORNAL_JIRA_CEILING=value), "NOCTORNAL_JIRA_CEILING") is refused


@pytest.mark.parametrize("name", ["NOCTORNAL_JIRA_CA_FILE", "NOCTORNAL_LOOKUP_CA_FILE"])
def test_a_ca_file_that_cannot_be_read_is_refused(name, tmp_path):
    assert _says(_problems(**{name: str(tmp_path / "missing.pem")}), name)
    present = tmp_path / "ca.pem"
    present.write_text("-----BEGIN CERTIFICATE-----\n", encoding="ascii")
    assert not _says(_problems(**{name: str(present)}), name)


def test_development_refuses_none_of_them():
    assert config.verify_environment({"NOCTORNAL_OUTBOUND_LOOKUPS": "on",
                                      "NOCTORNAL_WEBHOOK_ALLOW_HTTP": "1",
                                      "NOCTORNAL_JIRA_CEILING": "RED"}) == []


@pytest.mark.parametrize("raw,state", [("", "off"), ("off", "off"), (" OFF ", "off"),
                                       ("on", "on"), ("On ", "on"), ("yes", "invalid"),
                                       ("1", "invalid"), ("true", "invalid")])
def test_only_on_turns_the_host_switch_on(raw, state):
    assert providers.outbound_switch({"NOCTORNAL_OUTBOUND_LOOKUPS": raw}) == (state, raw)
    assert providers.outbound_switch({})[0] == "off"


def test_the_private_ca_is_for_your_own_instance_only(tmp_path, monkeypatch):
    import ssl
    ca = tmp_path / "ca.pem"
    ca.write_bytes(ssl.DER_cert_to_PEM_cert(_self_signed_der()).encode("ascii"))
    monkeypatch.setenv(providers.CA_FILE_ENV, str(ca))
    vendor = SimpleNamespace(use_private_ca=True, exposure_level="VENDOR")
    own = SimpleNamespace(use_private_ca=True, exposure_level="NONE")
    unasked = SimpleNamespace(use_private_ca=False, exposure_level="NONE")
    assert providers.ca_context_for(vendor) is None
    assert providers.ca_context_for(unasked) is None
    assert isinstance(providers.ca_context_for(own), ssl.SSLContext)


def _self_signed_der() -> bytes:
    """A certificate to load: the first one this host's default store holds."""
    import ssl
    context = ssl.create_default_context()
    certs = context.get_ca_certs(binary_form=True)
    if not certs:
        pytest.skip("no CA certificate on this host to stand in for a private CA")
    return certs[0]


def test_the_consequence_names_the_exposure_and_never_hedges():
    for level in providers.LEVELS:
        text = providers.consequence(level, network="10.20.0.0/24", basis="our contract")
        assert text and "(s)" not in text and chr(0x2014) not in text
    assert "10.20.0.0/24" in providers.consequence("NONE", network="10.20.0.0/24")
    assert "our contract" in providers.consequence("VENDOR", basis="our contract")
