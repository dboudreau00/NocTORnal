"""PGP verification: the one path in Phase 7 that produces a CONFIRMATION.

docs/10: "A message signed by a key whose fingerprint appears in the
contact block is real cryptographic evidence of control, not a claim."

Everything else in this phase produces claims, so this is the one place
where being wrong is worst -- a CONFIRMED binding is what docs/10 says may
carry weight in automatic identity resolution.

## These tests are NOT gated on gpg, deliberately

Every other environment-dependent leg in this suite is gated, and CI
fails the run if anything skips. gpg is present on the CI image, and if
it ever is not, the only cryptographic-evidence path in the system going
untested should break the build rather than quietly disappear from it.

The fixtures under `fixtures/pgp/` are a throwaway keypair generated once
with `gpg --quick-generate-key ed25519`. Vendoring them rather than
generating per-run keeps the tests deterministic and fast, and means they
do not need gpg-agent -- verification is a public-key operation and never
touches a secret key.

## The two traps carry this file

`test_a_signature_by_a_different_key_is_not_a_confirmation` and
`test_an_identifier_appended_below_the_signature_is_not_signed` are the
reason the module exists in this shape. Both describe attacks that a
plausible implementation passes.
"""
from __future__ import annotations

import pathlib

import pytest

from noctornal_api.pgp import (
    BAD_SIGNATURE,
    KEY_MISMATCH,
    KEY_UNAVAILABLE,
    MALFORMED,
    NO_VERIFIER,
    VALUE_NOT_IN_PAYLOAD,
    VERIFIED,
    PgpError,
    gpg_path,
    normalise_fingerprint,
    verify_clearsigned,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "pgp"


def _fix(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


VENDOR_FPR = _fix("vendor_fingerprint.txt").strip()
IMPOSTOR_FPR = _fix("impostor_fingerprint.txt").strip()
TOX_PUBKEY = _fix("tox_pubkey.txt").strip()
VENDOR_PUB = _fix("vendor_pub.asc")
IMPOSTOR_PUB = _fix("impostor_pub.asc")
SIGNED_WITH_TOX = _fix("signed_with_tox.asc")
SIGNED_WITHOUT_TOX = _fix("signed_without_tox.asc")
SIGNED_BY_IMPOSTOR = _fix("signed_by_impostor.asc")


def test_gpg_is_available_to_this_test_run():
    """A guard rather than a gate. If gpg disappears, the failure should
    be this one line and not eight confusing MALFORMED assertions."""
    assert gpg_path(), (
        "gpg is not on PATH. Verification is the only cryptographic-evidence "
        "path in this system and it must not silently go untested.")


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------

def test_a_signature_over_the_identifier_confirms_it():
    result = verify_clearsigned(
        SIGNED_WITH_TOX, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == VERIFIED
    assert result.confirms
    assert result.signing_fingerprint == VENDOR_FPR
    assert result.value_in_payload
    assert result.signed_payload_present()


def test_the_status_output_is_kept_for_re_reading():
    """A disputed verification should be re-readable rather than
    re-arguable."""
    result = verify_clearsigned(
        SIGNED_WITH_TOX, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert "VALIDSIG" in result.status_output
    assert result.verifier == "GPG"
    assert result.verifier_version


# ---------------------------------------------------------------------------
# TRAP 1 -- the wrong key
# ---------------------------------------------------------------------------

def test_a_signature_by_a_different_key_is_not_a_confirmation():
    """A signature proves control of whatever key signed it. If that is
    not the key the actor published, it is evidence about a stranger.

    The impostor signs the SAME text, containing the SAME Tox ID, with a
    valid signature by a real key. Everything checks out except the one
    thing that matters.
    """
    result = verify_clearsigned(
        SIGNED_BY_IMPOSTOR, IMPOSTOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == KEY_MISMATCH
    assert not result.confirms
    assert result.signing_fingerprint == IMPOSTOR_FPR
    assert VENDOR_FPR in result.detail and IMPOSTOR_FPR in result.detail


def test_a_message_signed_by_a_key_we_were_not_given_is_unverifiable():
    result = verify_clearsigned(
        SIGNED_WITH_TOX, IMPOSTOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == KEY_UNAVAILABLE
    assert not result.confirms


# ---------------------------------------------------------------------------
# TRAP 2 -- the replayed message
# ---------------------------------------------------------------------------

def test_an_identifier_appended_below_the_signature_is_not_signed():
    """THE test for this module.

    Everything after `-----END PGP SIGNATURE-----` in a clearsigned
    message is unsigned. So any message a vendor ever published can be
    reposted with an attacker's Tox ID pasted underneath, and the
    signature still verifies -- because the signature was never over that
    text.

    A `value in message` check passes here. The value IS in the message.
    """
    attacked = SIGNED_WITHOUT_TOX + f"\nTOX: {TOX_PUBKEY}\n"
    assert TOX_PUBKEY in attacked, "the attack premise: the value is present"

    result = verify_clearsigned(
        attacked, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == VALUE_NOT_IN_PAYLOAD
    assert not result.confirms
    assert not result.value_in_payload
    # The signature itself was fine -- which is what makes this dangerous.
    assert result.signing_fingerprint == VENDOR_FPR


def test_a_valid_signature_over_unrelated_text_confirms_nothing():
    result = verify_clearsigned(
        SIGNED_WITHOUT_TOX, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == VALUE_NOT_IN_PAYLOAD
    assert result.signing_fingerprint == VENDOR_FPR


def test_naming_no_identifier_confirms_no_identifier():
    """A valid signature with nothing named confirms control of the key
    and nothing about any selector."""
    result = verify_clearsigned(
        SIGNED_WITH_TOX, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=None)
    assert result.outcome == VALUE_NOT_IN_PAYLOAD
    assert not result.confirms


# ---------------------------------------------------------------------------
# Tampering and malformed input
# ---------------------------------------------------------------------------

def test_a_modified_body_fails_the_signature():
    tampered = SIGNED_WITH_TOX.replace("Vendor contact", "Vendor CONTACT")
    assert tampered != SIGNED_WITH_TOX
    result = verify_clearsigned(
        tampered, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == BAD_SIGNATURE


def test_a_swapped_identifier_fails_the_signature():
    """The attack the whole feature defends against: edit the Tox ID
    inside a signed block and repost it."""
    tampered = SIGNED_WITH_TOX.replace(TOX_PUBKEY, "B2" * 32)
    result = verify_clearsigned(
        tampered, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value="B2" * 32)
    assert result.outcome == BAD_SIGNATURE
    assert not result.confirms


@pytest.mark.parametrize("message", [
    "not a pgp message at all",
    "",
    "   ",
    "-----BEGIN PGP SIGNATURE-----\ngarbage\n-----END PGP SIGNATURE-----",
])
def test_junk_input_is_malformed_not_confirmed(message):
    result = verify_clearsigned(
        message, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == MALFORMED
    assert not result.confirms


def test_no_public_key_means_unverifiable_not_confirmed():
    result = verify_clearsigned(
        SIGNED_WITH_TOX, "", claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == KEY_UNAVAILABLE


def test_an_oversized_message_is_refused_before_reaching_a_subprocess():
    result = verify_clearsigned(
        "-----BEGIN PGP SIGNED MESSAGE-----\n" + "A" * 2_000_000,
        VENDOR_PUB, claimed_fingerprint=VENDOR_FPR)
    assert result.outcome == MALFORMED


# ---------------------------------------------------------------------------
# A missing verifier is a failure to LOOK
# ---------------------------------------------------------------------------

def test_an_absent_gpg_never_produces_a_confirmation(monkeypatch):
    """There must be no path in which the absence of a verifier reads as
    a successful verification."""
    monkeypatch.setenv("NOCTORNAL_GPG", "/nonexistent/gpg-binary")
    result = verify_clearsigned(
        SIGNED_WITH_TOX, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == NO_VERIFIER
    assert result.verifier == "NONE"
    assert not result.confirms
    assert not result.value_in_payload


def test_no_verifier_is_distinct_from_a_failed_verification(monkeypatch):
    """"nobody checked" and "checked and failed" must not look the same,
    or an unchecked claim reads as a checked-and-rejected one."""
    monkeypatch.setenv("NOCTORNAL_GPG", "/nonexistent/gpg-binary")
    unchecked = verify_clearsigned(
        SIGNED_WITH_TOX, VENDOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    monkeypatch.delenv("NOCTORNAL_GPG")
    failed = verify_clearsigned(
        SIGNED_BY_IMPOSTOR, IMPOSTOR_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert unchecked.outcome != failed.outcome


# ---------------------------------------------------------------------------
# Fingerprint formatting -- not cryptography
# ---------------------------------------------------------------------------

def test_a_spaced_fingerprint_matches_an_unspaced_one():
    """Fingerprints circulate printed in groups of four. A formatting
    difference must never surface as KEY_MISMATCH, which is the one
    outcome that accuses somebody."""
    spaced = " ".join(VENDOR_FPR[i:i + 4] for i in range(0, 40, 4))
    assert normalise_fingerprint(spaced) == VENDOR_FPR
    result = verify_clearsigned(
        SIGNED_WITH_TOX, VENDOR_PUB, claimed_fingerprint=spaced,
        confirms_value=TOX_PUBKEY)
    assert result.outcome == VERIFIED


@pytest.mark.parametrize("given,expected", [
    ("0x" + "a" * 40, "A" * 40),
    ("  " + "b" * 40 + "  ", "B" * 40),
    ("c" * 64, "C" * 64),                     # v5/v6 fingerprints
])
def test_fingerprint_forms_that_normalise(given, expected):
    assert normalise_fingerprint(given) == expected


@pytest.mark.parametrize("given", [
    "", "not hex", "A" * 39, "A" * 41, "G" * 40, None,
])
def test_things_that_are_not_fingerprints_are_refused(given):
    with pytest.raises(PgpError):
        normalise_fingerprint(given)


# ---------------------------------------------------------------------------
# Status-line injection -- the defect this module's whole shape exists for
# ---------------------------------------------------------------------------

INJECTION_FPR = _fix("injection_fingerprint.txt").strip()
INJECTION_PUB = _fix("injection_pub.asc")
INJECTION_SIGNED = _fix("injection_signed.asc")


def test_a_crafted_user_id_cannot_forge_a_validsig_line():
    """THE test for this module.

    An adversarial review broke every defence at once by attacking their
    shared input. gpg percent-escapes `%` and bytes below 0x20 in the
    attacker-controlled user-ID field, and escapes NOTHING at or above
    0x80. Python's `str.splitlines()` breaks on U+0085, U+2028 and U+2029.

    So a key whose user ID is

        Attacker Persona<U+0085>[GNUPG:] VALIDSIG <victim fpr> ...

    made gpg emit a forged status line inside GOODSIG -- which gpg emits
    BEFORE the real VALIDSIG -- and the parser read the forged one first.
    Outcome VERIFIED, signing fingerprint the VICTIM's, binding upgraded
    to CONFIRMED, for a key the attacker did not hold.

    The CHECK constraints could not catch it: `signing_fingerprint` and
    `claimed_fingerprint` both came from the same lied-to parse, so they
    agreed. A constraint defends against the application forgetting to
    check; it cannot defend against it checking a forged input.

    The fixture is a real key carrying that user ID.
    """
    result = verify_clearsigned(
        INJECTION_SIGNED, INJECTION_PUB, claimed_fingerprint=VENDOR_FPR,
        confirms_value=TOX_PUBKEY)
    assert result.outcome != VERIFIED
    assert not result.confirms
    # And it names the key that ACTUALLY signed, not the one it claimed.
    assert result.signing_fingerprint == INJECTION_FPR


def test_the_status_parser_splits_on_newline_and_nothing_else():
    """Locale-independent proof of the same thing.

    The end-to-end test above only fires where the host encoding maps
    those bytes to line terminators — it does on the Linux deployment
    target and does NOT on a cp1252 Windows dev box, which is exactly why
    953 green tests never saw the original defect. This one holds
    everywhere because it works on bytes.
    """
    from noctornal_api.pgp import _status_lines

    for terminator in (b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9"):
        stream = (b"[GNUPG:] GOODSIG DEADBEEF Attacker" + terminator
                  + b"[GNUPG:] VALIDSIG " + b"A" * 40 + b" 2026-01-01\n"
                  b"[GNUPG:] VALIDSIG " + b"B" * 40 + b" 2026-01-01\n")
        codes = [parts[0] for parts in _status_lines(stream) if parts]
        # Two real lines, never three: the forged one is part of the user
        # ID and stays inside GOODSIG where it belongs.
        assert codes == ["GOODSIG", "VALIDSIG"], terminator
        validsigs = [p[1] for p in _status_lines(stream)
                     if p and p[0] == "VALIDSIG"]
        assert validsigs == ["B" * 40], terminator


def test_two_valid_signatures_are_refused_rather_than_resolved_by_picking_one():
    """Taking the first of several is what made injection profitable, and
    is a guess on its own terms: a doubly-signed message has two answers."""
    from noctornal_api.pgp import _read_status

    stream = (b"[GNUPG:] GOODSIG X Signer\n"
              b"[GNUPG:] VALIDSIG " + b"A" * 40 + b" 2026-01-01\n"
              b"[GNUPG:] VALIDSIG " + b"B" * 40 + b" 2026-01-01\n")
    result = _read_status(stream, b"payload", claimed="A" * 40,
                          confirms_value=None, version=None)
    assert result.outcome == MALFORMED
    assert not result.confirms


def test_a_value_that_merely_occurs_inside_a_longer_number_is_not_confirmed():
    """Telegram durable values are bare digits, so a vendor signing an
    ordinary sentence with an order number in it could otherwise confirm a
    stranger's account -- and the same collision happens by accident,
    which is worse, because nothing about it looks like an attack."""
    from noctornal_api.pgp import _payload_contains

    present, why = _payload_contains(
        "Escrow order 3877451900 shipped 2026-07-25.", "77451")
    assert not present
    assert "longer run of characters" in why


def test_the_tox_case_still_confirms_from_a_full_76_hex_id():
    """The boundary rule must not break the commonest legitimate case: an
    actor prints the whole Tox ID, the durable value is its 64-hex head."""
    from noctornal_api.pgp import _payload_contains

    present, _ = _payload_contains(f"TOX: {'A1' * 38}", "A1" * 32)
    assert present


def test_a_signature_over_nothing_signed_does_not_store_a_payload_digest():
    """gpg writes its --output file even when the signature FAILS, so
    digesting it unconditionally recorded attacker plaintext under a
    column documented as "the exact bytes that were signed"."""
    from noctornal_api.pgp import _SIGNED_PAYLOAD_OUTCOMES
    assert BAD_SIGNATURE not in _SIGNED_PAYLOAD_OUTCOMES
    assert MALFORMED not in _SIGNED_PAYLOAD_OUTCOMES
    assert VERIFIED in _SIGNED_PAYLOAD_OUTCOMES
