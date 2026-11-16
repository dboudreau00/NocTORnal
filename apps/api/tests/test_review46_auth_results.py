"""An Authentication-Results header is believed only under a valid mail stamp (docs/17 http_ui-007).

Every byte of a message handed over as a file is somebody's claim. A sender who writes `Received: ...
by mx.<trusted host>` and an `Authentication-Results: mx.<trusted host>; dkim=pass
header.d=microsoft.com` above it passed the three positional rules this file used to hold, and the
message recorded DKIM as passed for a domain of the sender's choosing and proposed it as a durable,
"cryptographically authenticated" DOMAIN selector. The positional rules are gone: a header is believed
only when (1) a trusted MTA is declared (`NOCTORNAL_TRUSTED_MTA_HOSTS`), (2) an X-NocTORnal-Stamp the
deployment's own mail server added verifies under a key in the ring (`noctornal_api.mail_stamp`) and
attests that header, and (3) its authserv-id is a trusted MTA.

No database.
"""
from __future__ import annotations

import base64

import pytest

from mail_stamp_support import KEY, KEYS, stamped
from noctornal_api.deception import (
    AUTH_BASIS_STAMP,
    parse_eml,
    selector_candidates_for_email,
)

TRUSTED = ("corp.example",)
FORGED = (b"Authentication-Results: mx.corp.example; dkim=pass header.d=microsoft.com;"
          b" spf=pass smtp.mailfrom=microsoft.com; dmarc=pass header.from=microsoft.com\r\n")
#: The Received line the receiving server writes, which a forger writes as readily.
STAMP = (b"Received: from sender.example ([203.0.113.9]) by mx.corp.example;"
         b" Mon, 20 Jul 2026 09:00:00 +0000\r\n")
BODY = b"From: a@evil.example\r\nSubject: x\r\n\r\nbody\r\n"
OURS = (b"Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=acme.example;"
        b" dkim=pass header.d=acme.example; dmarc=pass header.from=acme.example\r\n")
GOOD = OURS + STAMP + b"From: jane@acme.example\r\nSubject: Remittance\r\n\r\nbody\r\n"


def _domains(parsed):
    return {c["value"] for c in selector_candidates_for_email(parsed)
            if c["selector_type"] == "DOMAIN"}


def _gap(parsed):
    return [g["reason"] for g in parsed.gaps if g["step"] == "authentication_results"]


def _nothing_recorded(parsed, claim=b"microsoft.com"):
    assert (parsed.spf_result, parsed.dkim_result, parsed.dmarc_result) == (None, None, None)
    assert (parsed.spf_domain, parsed.dkim_domain, parsed.dmarc_domain) == (None, None, None)
    assert parsed.auth_basis is None
    assert claim.decode() not in _domains(parsed)
    assert parsed.auth_results_raw and claim.decode() in parsed.auth_results_raw, (
        "the header is kept for the analyst, as the sender's claim")
    gap = next(g for g in _gap(parsed) if "NOT believed" in g)
    return gap


# --- the register's case ------------------------------------------------------------------------

def test_a_forged_received_and_a_forged_authentication_results_above_it_are_not_believed_without_a_stamp():
    """THE forgery: every positional rule the parser used to apply is satisfied, and nothing is
    believed, because nothing in the message is the deployment's own server's MAC."""
    parsed = parse_eml(FORGED + STAMP + BODY, trusted=TRUSTED, stamp_keys=KEYS)
    gap = _nothing_recorded(parsed)
    assert "no X-NocTORnal-Stamp" in gap


def test_the_same_forgery_with_a_stamp_the_sender_computed_is_not_believed():
    forged = stamped(FORGED + STAMP + BODY, key=bytes(32))
    gap = _nothing_recorded(parse_eml(forged, trusted=TRUSTED, stamp_keys=KEYS))
    assert "does not verify" in gap


def test_a_stamp_copied_from_another_message_is_not_believed():
    real = stamped(GOOD)
    stamp_line = real.split(b"\r\n", 1)[0] + b"\r\n"
    copied = stamp_line + FORGED + STAMP + BODY
    gap = _nothing_recorded(parse_eml(copied, trusted=TRUSTED, stamp_keys=KEYS))
    assert "does not match" in gap


def test_a_stamped_message_whose_reply_to_was_edited_is_not_believed():
    edited = stamped(GOOD.replace(b"Subject:", b"Reply-To: jane@acme.example\r\nSubject:"))
    edited = edited.replace(b"Reply-To: jane@acme.example", b"Reply-To: jane.acme@gmail.example")
    gap = _nothing_recorded(parse_eml(edited, trusted=TRUSTED, stamp_keys=KEYS),
                            claim=b"acme.example")
    assert "does not verify" in gap


# --- both directions: what a stamped message still records --------------------------------------

def test_a_stamped_message_records_the_verdict_and_proposes_the_durable_domain():
    parsed = parse_eml(stamped(GOOD), trusted=TRUSTED, stamp_keys=KEYS)
    assert (parsed.spf_result, parsed.dkim_result, parsed.dmarc_result) == (
        "PASS", "PASS", "PASS")
    assert parsed.dkim_domain == "acme.example"
    assert parsed.auth_basis == AUTH_BASIS_STAMP
    durable = [c for c in selector_candidates_for_email(parsed)
               if c["strength"] == "durable" and c["selector_type"] == "DOMAIN"]
    assert [c["value"] for c in durable] == ["acme.example"]
    assert _gap(parsed) == []


def test_a_stamped_message_with_the_header_below_a_later_relays_received_line_is_believed():
    """The positional rules are gone: a relay inside the organisation may add its own Received line,
    and a header of its own, above the stamped ones."""
    later = (b"Received: from mx.corp.example ([10.0.0.5]) by mailbox.corp.example with LMTP;"
             b" Mon, 20 Jul 2026 09:00:05 +0000\r\n" + stamped(GOOD))
    parsed = parse_eml(later, trusted=TRUSTED, stamp_keys=KEYS)
    assert parsed.dkim_domain == "acme.example" and parsed.auth_basis == AUTH_BASIS_STAMP


def test_the_header_the_stamp_covers_is_the_verdict_and_not_one_put_above_it():
    parsed = parse_eml(FORGED + stamped(GOOD), trusted=TRUSTED, stamp_keys=KEYS)
    assert parsed.dkim_domain == "acme.example"
    assert "microsoft.com" not in _domains(parsed)
    assert any("Authentication-Results headers were present" in g for g in _gap(parsed))


def test_a_subdomain_of_a_trusted_suffix_is_one_of_ours():
    raw = (b"Authentication-Results: mx3.eu.corp.example 1; dkim=pass header.d=acme.example\r\n"
           + b"Received: from s.example ([203.0.113.9]) by relay.eu.corp.example;"
             b" Mon, 20 Jul 2026 09:00:00 +0000\r\n" + BODY)
    assert parse_eml(stamped(raw), trusted=TRUSTED, stamp_keys=KEYS).dkim_domain == "acme.example"


def test_a_stamped_header_whose_authserv_id_is_not_ours_is_not_believed():
    """Rule (1) of the old three, kept: the stamp says our server attested the header, and
    NOCTORNAL_TRUSTED_MTA_HOSTS still says which names are ours."""
    raw = FORGED.replace(b"mx.corp.example", b"mx.attacker.example") + STAMP + BODY
    gap = _nothing_recorded(parse_eml(stamped(raw), trusted=TRUSTED, stamp_keys=KEYS))
    assert "authserv-id" in gap


@pytest.mark.parametrize("authserv", [b"corp.example.attacker.example", b"notcorp.example",
                                      b"dkim=pass", b"", b"mx.corp.example.evil"])
def test_a_look_alike_authserv_id_is_not_ours(authserv):
    raw = (b"Authentication-Results: " + authserv + b"; dkim=pass header.d=microsoft.com\r\n"
           + STAMP + BODY)
    parsed = parse_eml(stamped(raw), trusted=TRUSTED, stamp_keys=KEYS)
    assert parsed.dkim_result is None and parsed.dkim_domain is None
    assert "microsoft.com" not in _domains(parsed)


# --- the environment ----------------------------------------------------------------------------

def test_with_no_key_configured_no_header_is_attributed(monkeypatch):
    for name in ("NOCTORNAL_MAIL_STAMP_KEY", "NOCTORNAL_MAIL_STAMP_KEY_ID",
                 "NOCTORNAL_MAIL_STAMP_KEY_RETIRED"):
        monkeypatch.delenv(name, raising=False)
    parsed = parse_eml(stamped(GOOD), trusted=TRUSTED)
    gap = _nothing_recorded(parsed, claim=b"acme.example")
    assert "NOCTORNAL_MAIL_STAMP_KEY" in gap


def test_an_unreadable_key_ring_believes_nothing(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_MAIL_STAMP_KEY", base64.b64encode(KEY[:8]).decode())
    parsed = parse_eml(stamped(GOOD), trusted=TRUSTED)
    assert "key ring in this server's environment" in _nothing_recorded(
        parsed, claim=b"acme.example")
    assert base64.b64encode(KEY[:8]).decode() not in " ".join(_gap(parsed))


def test_with_no_trusted_mta_declared_no_header_is_attributed(monkeypatch):
    """Unconfigured means unknown: the answer the infrastructure selectors already give."""
    monkeypatch.delenv("NOCTORNAL_TRUSTED_MTA_HOSTS", raising=False)
    parsed = parse_eml(stamped(GOOD), stamp_keys=KEYS)
    assert "no trusted MTA is declared" in _nothing_recorded(parsed, claim=b"acme.example")


def test_the_declared_environment_is_what_trusts_a_header_by_default(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_TRUSTED_MTA_HOSTS", "corp.example")
    monkeypatch.setenv("NOCTORNAL_MAIL_STAMP_KEY", base64.b64encode(KEY).decode())
    monkeypatch.setenv("NOCTORNAL_MAIL_STAMP_KEY_ID", "mail:t1")
    monkeypatch.delenv("NOCTORNAL_MAIL_STAMP_KEY_RETIRED", raising=False)
    parsed = parse_eml(stamped(GOOD))
    assert parsed.dkim_result == "PASS" and parsed.dkim_domain == "acme.example"
    # The same environment and the forgery: still nothing.
    _nothing_recorded(parse_eml(FORGED + STAMP + BODY))


def test_a_second_authentication_results_header_is_recorded_not_believed():
    raw = (b"Authentication-Results: mx.corp.example; dkim=fail header.d=evil.example\r\n"
           + STAMP + FORGED + BODY)
    parsed = parse_eml(stamped(raw), trusted=TRUSTED, stamp_keys=KEYS)
    assert parsed.dkim_result == "FAIL" and parsed.dkim_domain is None
    assert "microsoft.com" not in _domains(parsed)
    assert any("Authentication-Results headers were present" in g
               for g in _gap(parsed))
    assert "microsoft.com" in parsed.auth_results_raw


def test_more_stamps_than_are_read_are_a_gap():
    junk = b"X-NocTORnal-Stamp: nonsense\r\n" * 5
    parsed = parse_eml(junk + stamped(GOOD), trusted=TRUSTED, stamp_keys=KEYS)
    assert parsed.dkim_result is None
    assert any("6 X-NocTORnal-Stamp headers were present" in g for g in _gap(parsed))
