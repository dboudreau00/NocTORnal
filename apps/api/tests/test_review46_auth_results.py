"""http_ui-007 (review of 2026-10-03).

The parser believed the FIRST Authentication-Results header and never asked
who wrote it. A message the receiving server stamped nothing on (forwarded,
exported) carries only the sender's own header, and the sender chooses which
domain it says passed: `dkim=pass header.d=microsoft.com` became a durable,
"cryptographically authenticated" DOMAIN selector, in the same output that
said no trusted MTA was recognised in the chain.

The header is now believed only when (1) its authserv-id is a trusted MTA
(`NOCTORNAL_TRUSTED_MTA_HOSTS`), (2) the topmost Received header was written
by a trusted MTA and (3) it sits above every Received header, because an MTA
prepends and a header below one was written before that hop saw the message.

Fails on dc28ffa: the forged header's verdicts and domains are recorded. No
database.
"""
from __future__ import annotations

import pytest

from noctornal_api.deception import (
    parse_eml,
    selector_candidates_for_email,
)

TRUSTED = ("corp.example",)
FORGED = (b"Authentication-Results: mx.corp.example; dkim=pass header.d=microsoft.com;"
          b" spf=pass smtp.mailfrom=microsoft.com; dmarc=pass header.from=microsoft.com\r\n")
STAMP = (b"Received: from sender.example ([203.0.113.9]) by mx.corp.example;"
         b" Mon, 20 Jul 2026 09:00:00 +0000\r\n")
BODY = b"From: a@evil.example\r\nSubject: x\r\n\r\nbody\r\n"


def _domains(parsed):
    return {c["value"] for c in selector_candidates_for_email(parsed)
            if c["selector_type"] == "DOMAIN"}


def _gap(parsed):
    return [g["reason"] for g in parsed.gaps if g["step"] == "authentication_results"]


def _nothing_recorded(parsed):
    assert (parsed.spf_result, parsed.dkim_result, parsed.dmarc_result) == (None, None, None)
    assert (parsed.spf_domain, parsed.dkim_domain, parsed.dmarc_domain) == (None, None, None)
    assert "microsoft.com" not in _domains(parsed)
    assert parsed.auth_results_raw and "microsoft.com" in parsed.auth_results_raw, (
        "the header is kept for the analyst, as the sender's claim")
    (gap,) = _gap(parsed)
    assert "NOT believed" in gap
    return gap


def test_a_lone_sender_written_header_is_not_a_verdict_and_not_a_selector():
    """The reviewer's message: a trusted-looking authserv-id, written by the
    sender, below the Received line our own MTA stamped."""
    parsed = parse_eml(STAMP + FORGED + BODY, trusted=TRUSTED)
    gap = _nothing_recorded(parsed)
    assert "sits below a Received header" in gap


def test_a_lone_header_with_no_received_line_at_all_is_not_believed():
    parsed = parse_eml(FORGED + BODY, trusted=TRUSTED)
    assert "no Received header" in _nothing_recorded(parsed)


def test_a_forged_header_above_a_relay_the_sender_chose_is_not_believed():
    """A relay outside the boundary may write a header at the top of ITS
    stack, which sits below our own MTA's Received line."""
    raw = (STAMP
           + FORGED
           + b"Received: from evil.example ([203.0.113.7]) by evil-relay.example;"
             b" Mon, 20 Jul 2026 08:59:00 +0000\r\n" + BODY)
    assert "sits below" in _nothing_recorded(parse_eml(raw, trusted=TRUSTED))


def test_a_header_whose_authserv_id_is_not_ours_is_not_believed():
    raw = (FORGED.replace(b"mx.corp.example", b"mx.attacker.example") + STAMP + BODY)
    assert "authserv-id" in _nothing_recorded(parse_eml(raw, trusted=TRUSTED))


@pytest.mark.parametrize("authserv", [b"corp.example.attacker.example", b"notcorp.example",
                                      b"dkim=pass", b"", b"mx.corp.example.evil"])
def test_a_look_alike_authserv_id_is_not_ours(authserv):
    raw = (b"Authentication-Results: " + authserv + b"; dkim=pass header.d=microsoft.com\r\n"
           + STAMP + BODY)
    parsed = parse_eml(raw, trusted=TRUSTED)
    assert parsed.dkim_result is None and parsed.dkim_domain is None
    assert "microsoft.com" not in _domains(parsed)


def test_with_no_trusted_mta_declared_no_header_is_attributed(monkeypatch):
    """Unconfigured means unknown: the answer the infrastructure selectors
    already give."""
    monkeypatch.delenv("NOCTORNAL_TRUSTED_MTA_HOSTS", raising=False)
    parsed = parse_eml(FORGED + STAMP + BODY)
    assert "no trusted MTA is declared" in _nothing_recorded(parsed)


def test_the_declared_environment_is_what_trusts_a_header_by_default(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_TRUSTED_MTA_HOSTS", "corp.example")
    parsed = parse_eml(FORGED + STAMP + BODY)
    assert parsed.dkim_result == "PASS" and parsed.dkim_domain == "microsoft.com", (
        "stamped above our own Received line, so it is the receiving server's")


def test_the_last_server_to_handle_the_message_must_be_ours():
    outside = (b"Received: from corp.example ([10.0.0.5]) by mailbox.provider.example;"
               b" Mon, 20 Jul 2026 09:05:00 +0000\r\n")
    raw = FORGED + outside + STAMP + BODY
    assert "not a trusted MTA" in _nothing_recorded(parse_eml(raw, trusted=TRUSTED))


# --- both directions: what a stamped message still records ------------------

def test_the_receiving_servers_own_header_above_its_received_line_is_believed():
    raw = (b"Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=acme.example;"
           b" dkim=pass header.d=acme.example; dmarc=pass header.from=acme.example\r\n"
           + STAMP + BODY)
    parsed = parse_eml(raw, trusted=TRUSTED)
    assert (parsed.spf_result, parsed.dkim_result, parsed.dmarc_result) == (
        "PASS", "PASS", "PASS")
    assert parsed.dkim_domain == "acme.example"
    durable = [c for c in selector_candidates_for_email(parsed)
               if c["strength"] == "durable" and c["selector_type"] == "DOMAIN"]
    assert [c["value"] for c in durable] == ["acme.example"]
    assert _gap(parsed) == []


def test_a_subdomain_of_a_trusted_suffix_is_one_of_ours():
    raw = (b"Authentication-Results: mx3.eu.corp.example 1; dkim=pass header.d=acme.example\r\n"
           + b"Received: from s.example ([203.0.113.9]) by relay.eu.corp.example;"
             b" Mon, 20 Jul 2026 09:00:00 +0000\r\n" + BODY)
    assert parse_eml(raw, trusted=TRUSTED).dkim_domain == "acme.example"


def test_an_appended_second_header_still_does_not_win():
    """The earlier rule is untouched: the first is the candidate, the
    others are recorded and not believed."""
    raw = (b"Authentication-Results: mx.corp.example; dkim=fail header.d=evil.example\r\n"
           + STAMP + FORGED + BODY)
    parsed = parse_eml(raw, trusted=TRUSTED)
    assert parsed.dkim_result == "FAIL" and parsed.dkim_domain is None
    assert "microsoft.com" not in _domains(parsed)
    assert any("Authentication-Results headers were present" in g
               for g in _gap(parsed))
