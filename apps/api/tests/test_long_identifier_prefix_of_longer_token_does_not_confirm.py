"""A long identifier is not confirmed by the start of a longer token.

A signature confirms a durable value when the signer published that value. A
40-hex fingerprint or a 64-hex key that is only the head of some longer run of
characters was not published. The one prefix that counts is the Tox case: the
64-hex public key followed by exactly the twelve hex digits of nospam and
checksum, which is the 76-hex Tox id an actor prints. No database.
"""
from __future__ import annotations

from noctornal_api.pgp import _payload_contains

TOX_PK = "A1" * 32
FINGERPRINT = "4A2B1C9D8E7F00112233445566778899AABBCCDD"


def test_a_fingerprint_that_prefixes_a_longer_token_is_not_confirmed():
    present, why = _payload_contains(f"hash {FINGERPRINT}deadbeef", FINGERPRINT)
    assert present is False
    assert "longer run of characters" in why


def test_a_64_hex_key_with_a_tail_that_is_not_a_tox_id_is_not_confirmed():
    for tail in ("deadbeef", "CD" * 7, "CD" * 6 + "zz", "CD" * 5 + "C"):
        present, _why = _payload_contains(f"id {TOX_PK}{tail}", TOX_PK)
        assert present is False, tail


def test_the_tox_id_still_confirms_its_public_key():
    for text in (f"TOX: {TOX_PK}{'CD' * 6}", f"TOX: {TOX_PK}{'cd' * 6}.",
                 f"{TOX_PK}{'CD' * 6}"):
        present, _why = _payload_contains(text, TOX_PK)
        assert present is True, text


def test_a_long_value_delimited_at_both_ends_still_confirms():
    present, _why = _payload_contains(f"fpr {FINGERPRINT} signed", FINGERPRINT)
    assert present is True
