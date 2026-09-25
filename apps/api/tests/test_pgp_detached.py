"""Detached signatures, signing subkeys, the packet walker, the agent and
the version floor (F10a, comms, 2026-09-24).

Not gated on gpg, as test_pgp.py is not: gpg is on the CI image, and the
only cryptographic-evidence path in the system going untested should break
the build rather than disappear from it.

The fixtures were generated once on the development host with a throwaway
key (a certify-only primary and a signing subkey) whose secret was then
discarded, as the older fixtures were. The shapes that must never reach
gpg (secret packets, a signature followed by a literal packet, partial
lengths) are built here from bytes, never stored as keys.
"""
from __future__ import annotations

import base64
import subprocess

import pytest

from noctornal_api import pgp
from noctornal_api.pgp import (
    BAD_SIGNATURE,
    DETACHED,
    MALFORMED,
    NO_VERIFIER,
    VALUE_NOT_IN_PAYLOAD,
    VERIFIED,
    PgpShapeError,
    _detached_shape,
    _pgp_packets,
    _public_key_shape,
    _read_status,
    verify_clearsigned,
    verify_detached,
)
from pgp_support import (
    SUB_PRIMARY,
    SUB_PUB,
    SUB_SIGNING,
    TOX_PUBKEY,
    VENDOR_PUB,
    fix,
    fix_bytes,
)

DATA = fix_bytes("detached_data.txt")
DATA_CRLF = fix_bytes("detached_data_crlf.txt")
BINARY_SIG = fix_bytes("detached_binary.sig")
ARMOURED_SIG = fix_bytes("detached_binary.asc")
TEXT_SIG = fix_bytes("detached_text.asc")


def _no_subprocess(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("a subprocess was started for input the walker "
                             "should have refused")
    monkeypatch.setattr(subprocess, "run", refuse)


def _armour(kind: str, data: bytes, header: bytes = b"") -> bytes:
    body = base64.b64encode(data)
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return (b"-----BEGIN PGP " + kind.encode() + b"-----" + header + b"\n\n"
            + b"\n".join(lines) + b"\n-----END PGP " + kind.encode() + b"-----\n")


def _packet(tag: int, body: bytes) -> bytes:
    return bytes([0xC0 | tag, len(body)]) + body


def _vendor_packets() -> bytes:
    """The vendor key's own binary packet stream, read out of its armour."""
    text = VENDOR_PUB.encode()
    body = b"".join(line for line in text.split(b"\n")[2:]
                    if line and not line.startswith((b"=", b"-----")))
    return base64.b64decode(body)


# ---------------------------------------------------------------------------
# Signing subkeys
# ---------------------------------------------------------------------------

def test_a_signature_by_a_signing_subkey_confirms_against_the_published_primary():
    """Vendors publish the primary and sign with a subkey. VALIDSIG's
    first field is the subkey; reading only it recorded every genuine
    subkey signature as KEY_MISMATCH."""
    result = verify_clearsigned(fix("subkey_signed_with_tox.asc"), SUB_PUB,
                                claimed_fingerprint=SUB_PRIMARY,
                                confirms_value=TOX_PUBKEY)
    assert result.outcome == VERIFIED, result.detail
    assert result.signing_fingerprint == SUB_SIGNING
    assert result.signing_primary_fingerprint == SUB_PRIMARY
    assert f"subkey {SUB_SIGNING} of key {SUB_PRIMARY}" in result.detail


def test_a_claimed_subkey_fingerprint_also_matches():
    result = verify_clearsigned(fix("subkey_signed_with_tox.asc"), SUB_PUB,
                                claimed_fingerprint=SUB_SIGNING,
                                confirms_value=TOX_PUBKEY)
    assert result.outcome == VERIFIED


# ---------------------------------------------------------------------------
# Detached signatures
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("signature", [BINARY_SIG, ARMOURED_SIG, TEXT_SIG],
                         ids=["binary", "armoured", "text-mode"])
def test_a_detached_signature_over_the_identifier_confirms_it(signature):
    result = verify_detached(signature, DATA, SUB_PUB,
                             claimed_fingerprint=SUB_PRIMARY,
                             confirms_value=TOX_PUBKEY)
    assert result.outcome == VERIFIED, result.detail
    assert result.form == DETACHED
    assert result.signature_class in ("00", "01")
    # The payload digested is the data supplied, which gpg checked whole.
    assert result.signed_payload == DATA


def test_a_detached_signature_over_other_data_is_bad():
    result = verify_detached(BINARY_SIG, DATA.replace(b"Vendor", b"Vandor"),
                             SUB_PUB, claimed_fingerprint=SUB_PRIMARY,
                             confirms_value=TOX_PUBKEY)
    assert result.outcome == BAD_SIGNATURE


def test_a_detached_signature_over_data_without_the_value_is_value_not_in_payload():
    result = verify_detached(fix_bytes("detached_no_tox.asc"),
                             fix_bytes("detached_no_tox_data.txt"), SUB_PUB,
                             claimed_fingerprint=SUB_PRIMARY,
                             confirms_value=TOX_PUBKEY)
    assert result.outcome == VALUE_NOT_IN_PAYLOAD


def test_a_text_mode_detached_signature_verifies_across_line_endings():
    """A class 01 signature is over canonical text, so a CRLF copy of the
    file still verifies."""
    result = verify_detached(TEXT_SIG, DATA_CRLF, SUB_PUB,
                             claimed_fingerprint=SUB_PRIMARY,
                             confirms_value=TOX_PUBKEY)
    assert result.outcome == VERIFIED
    assert result.signature_class == "01"


def test_a_binary_signature_over_pasted_text_names_line_endings():
    """A class 00 signature over a copy that changed its line endings is
    BAD; when the data was pasted, the detail says why before anyone
    reads it as forged."""
    result = verify_detached(BINARY_SIG, DATA_CRLF, SUB_PUB,
                             claimed_fingerprint=SUB_PRIMARY,
                             confirms_value=TOX_PUBKEY, data_was_pasted=True)
    assert result.outcome == BAD_SIGNATURE
    assert "line endings" in result.detail
    uploaded = verify_detached(BINARY_SIG, DATA_CRLF, SUB_PUB,
                               claimed_fingerprint=SUB_PRIMARY,
                               confirms_value=TOX_PUBKEY)
    assert "line endings" not in uploaded.detail


def test_an_opaque_signed_message_offered_as_a_detached_signature_is_refused_before_gpg(
        monkeypatch):
    _no_subprocess(monkeypatch)
    result = verify_detached(fix_bytes("opaque_signed.asc"), DATA, SUB_PUB,
                             claimed_fingerprint=SUB_PRIMARY)
    assert result.outcome == MALFORMED


def test_a_clearsigned_message_offered_as_a_detached_signature_is_refused_before_gpg(
        monkeypatch):
    _no_subprocess(monkeypatch)
    result = verify_detached(fix_bytes("subkey_signed_with_tox.asc"), DATA,
                             SUB_PUB, claimed_fingerprint=SUB_PRIMARY)
    assert result.outcome == MALFORMED


def test_an_old_style_signature_plus_literal_is_refused_before_gpg(monkeypatch):
    """A signature followed by a literal packet under SIGNATURE armour:
    gpg would check the literal, not the data beside it."""
    _no_subprocess(monkeypatch)
    result = verify_detached(fix_bytes("old_style_sig_plus_literal.asc"), DATA,
                             SUB_PUB, claimed_fingerprint=SUB_PRIMARY,
                             confirms_value="B2" * 32)
    assert result.outcome == MALFORMED
    assert "one signature packet" in result.detail


def test_a_signature_that_is_not_over_a_document_is_refused_before_gpg():
    """A v4 signature packet of class 0x13 (a certification) in the
    detached slot."""
    body = bytearray(BINARY_SIG[2:])
    body[1] = 0x13
    with pytest.raises(PgpShapeError):
        _detached_shape(bytes([0x88, len(body)]) + bytes(body))


def test_a_plaintext_status_line_in_detached_mode_is_refused():
    """Synthetic status bytes, so the defence does not depend on the
    host's gpg refusing the shape first."""
    status = (b"[GNUPG:] NEWSIG\n[GNUPG:] PLAINTEXT 62 0 x.txt\n"
              b"[GNUPG:] GOODSIG AAAA Vendor\n"
              b"[GNUPG:] VALIDSIG " + SUB_PRIMARY.encode()
              + b" 2026-09-24 1 0 4 0 22 10 00 " + SUB_PRIMARY.encode() + b"\n")
    result = _read_status(status, DATA, claimed=SUB_PRIMARY,
                          confirms_value=TOX_PUBKEY, version=None, form=DETACHED)
    assert result.outcome == MALFORMED
    assert "signed data of its own" in result.detail
    clearsigned = _read_status(status, DATA, claimed=SUB_PRIMARY,
                               confirms_value=TOX_PUBKEY, version=None)
    assert clearsigned.outcome == VERIFIED


def test_two_goodsig_lines_are_refused():
    status = (b"[GNUPG:] GOODSIG AAAA Vendor\n[GNUPG:] GOODSIG AAAA Vendor\n"
              b"[GNUPG:] VALIDSIG " + SUB_PRIMARY.encode()
              + b" 2026-09-24 1 0 4 0 22 10 01 " + SUB_PRIMARY.encode() + b"\n")
    result = _read_status(status, DATA, claimed=SUB_PRIMARY,
                          confirms_value=TOX_PUBKEY, version=None)
    assert result.outcome == MALFORMED


def test_two_newsig_lines_are_refused():
    status = (b"[GNUPG:] NEWSIG\n[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG AAAA Vendor\n"
              b"[GNUPG:] VALIDSIG " + SUB_PRIMARY.encode()
              + b" 2026-09-24 1 0 4 0 22 10 01 " + SUB_PRIMARY.encode() + b"\n")
    result = _read_status(status, DATA, claimed=SUB_PRIMARY,
                          confirms_value=TOX_PUBKEY, version=None)
    assert result.outcome == MALFORMED


def test_a_good_signature_of_a_non_document_class_is_not_verified():
    status = (b"[GNUPG:] GOODSIG AAAA Vendor\n"
              b"[GNUPG:] VALIDSIG " + SUB_PRIMARY.encode()
              + b" 2026-09-24 1 0 4 0 22 10 13 " + SUB_PRIMARY.encode() + b"\n")
    result = _read_status(status, DATA, claimed=SUB_PRIMARY,
                          confirms_value=TOX_PUBKEY, version=None)
    assert result.outcome == MALFORMED


# ---------------------------------------------------------------------------
# The packet walker, on keys
# ---------------------------------------------------------------------------

def test_a_public_key_block_wrapping_a_secret_packet_is_refused_before_gpg(
        monkeypatch):
    _no_subprocess(monkeypatch)
    armoured = _armour("PUBLIC KEY BLOCK", _packet(5, b"\x04" + b"\x00" * 40))
    with pytest.raises(PgpShapeError, match="SECRET key"):
        _public_key_shape(armoured)
    result = verify_clearsigned(fix("subkey_signed_with_tox.asc"),
                                armoured.decode(), claimed_fingerprint=SUB_PRIMARY)
    assert result.outcome == MALFORMED


def test_a_binary_key_with_a_secret_packet_after_the_public_one_is_refused_before_gpg(
        monkeypatch):
    _no_subprocess(monkeypatch)
    stream = _vendor_packets() + _packet(7, b"\x04" + b"\x00" * 40)
    with pytest.raises(PgpShapeError, match="SECRET key"):
        _public_key_shape(stream)


def test_a_private_key_block_is_refused_by_its_armour():
    with pytest.raises(PgpShapeError, match="SECRET key"):
        _public_key_shape(_armour("PRIVATE KEY BLOCK", _packet(5, b"\x04")))


def test_a_trust_packet_is_not_key_material():
    """Trust packets live only in local keyrings; a forged one is how a
    subkey is attached to somebody else's key (gpg.fail, trust)."""
    with pytest.raises(PgpShapeError, match="type 12"):
        _public_key_shape(_vendor_packets() + _packet(12, b"\x00\x00"))


@pytest.mark.parametrize("stream", [
    bytes([0xC6, 0xE1]) + b"\x00" * 4,        # new format, partial length
    bytes([0x9B]) + b"\x04" * 8,              # old format, indeterminate length
], ids=["partial", "indeterminate"])
def test_a_partial_or_indeterminate_length_packet_is_refused(stream):
    with pytest.raises(PgpShapeError):
        _pgp_packets(stream, armour_kinds=frozenset())


def test_a_truncated_packet_is_refused():
    with pytest.raises(PgpShapeError, match="past the end"):
        _pgp_packets(bytes([0xC6, 50]) + b"\x04" * 10, armour_kinds=frozenset())


def test_a_header_ending_in_a_tab_hides_nothing():
    """gpg reads an armour header that ends in a tab, so the walker must
    read the same block."""
    hidden = _armour("PUBLIC KEY BLOCK", _packet(5, b"\x04" + b"\x00" * 8),
                     header=b"\t")
    with pytest.raises(PgpShapeError, match="SECRET key"):
        _public_key_shape(hidden)


def test_a_second_block_after_forum_text_is_walked_too():
    """A clean key, forum prose, then a second block whose header ends in
    spaces and carries a secret packet: gpg imports both, so both are read
    and the secret packet refuses the lot."""
    clean = VENDOR_PUB.encode()
    hidden = _armour("PUBLIC KEY BLOCK", _packet(5, b"\x04" + b"\x00" * 8),
                     header=b"   ")
    with pytest.raises(PgpShapeError, match="SECRET key"):
        _public_key_shape(clean + b"\nposted by the vendor, see below\n" + hidden)


def test_an_armour_line_the_reader_cannot_place_is_refused():
    odd = VENDOR_PUB.encode() + b"\n-----BEGIN PGP MESSAGE, PART 1/2-----\n"
    with pytest.raises(PgpShapeError, match="not one this reader can place"):
        _public_key_shape(odd)


def test_a_crlf_key_and_a_utf8_comment_are_accepted():
    """Two shapes that once failed: both verify today."""
    crlf = VENDOR_PUB.replace("\n", "\r\n").encode()
    assert _public_key_shape(crlf)[0][0] == 6
    commented = VENDOR_PUB.replace(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: Jürgen's key\n",
    ).encode("utf-8")
    assert _public_key_shape(b"Forum post \xc2\xa9 2026\n" + commented)[0][0] == 6


def test_every_existing_fixture_key_passes_the_walker():
    for name in ("vendor_pub.asc", "impostor_pub.asc", "injection_pub.asc",
                 "subkey_pub.asc", "multi_key_pub.asc", "revoked_pub.asc"):
        assert _public_key_shape(fix_bytes(name)), name
    assert _public_key_shape(fix_bytes("wkd_vendor.bin"))


# ---------------------------------------------------------------------------
# No agent, relative paths, one budget
# ---------------------------------------------------------------------------

def test_every_gpg_invocation_carries_no_autostart_and_only_relative_paths(
        monkeypatch):
    seen = []
    real = subprocess.run

    def spy(argv, *a, **k):
        seen.append(list(argv))
        return real(argv, *a, **k)

    monkeypatch.setattr(subprocess, "run", spy)
    pgp._version_line.cache_clear()
    verify_detached(BINARY_SIG, DATA, SUB_PUB, claimed_fingerprint=SUB_PRIMARY,
                    confirms_value=TOX_PUBKEY)
    verify_clearsigned(fix("subkey_signed_with_tox.asc"), SUB_PUB,
                       claimed_fingerprint=SUB_PRIMARY)
    runs = [argv for argv in seen if "--version" not in argv]
    assert len(runs) == 4
    import re
    for argv in runs:
        assert "--no-autostart" in argv
        for item in argv[1:]:
            assert not item.startswith("/") and not re.match(r"^[A-Za-z]:", item), argv


def test_the_budget_is_shared_across_runs(monkeypatch):
    """One budget per keyring: the second run gets the remainder, and an
    exhausted budget raises before a third starts."""
    clock = {"now": 1000.0}
    monkeypatch.setattr(pgp, "_monotonic", lambda: clock["now"])
    timeouts = []

    def fake_run(argv, *a, **k):
        timeouts.append(k["timeout"])
        clock["now"] += 8.0
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pgp._EphemeralGpg("gpg") as gpg:
        gpg.run("--one")
        gpg.run("--two")
        clock["now"] += 5.0
        with pytest.raises(subprocess.TimeoutExpired):
            gpg.run("--three")
    assert timeouts == [pgp.GPG_TIMEOUT_SECONDS, pgp.GPG_TIMEOUT_SECONDS - 8.0]


# ---------------------------------------------------------------------------
# The version floor
# ---------------------------------------------------------------------------

@pytest.fixture
def stub_version(monkeypatch):
    def use(line: str | None):
        monkeypatch.setattr(pgp, "_version_line", lambda path: line)
    return use


@pytest.mark.parametrize("line,passes", [
    ("gpg (GnuPG) 2.4.9", True),
    ("gpg (GnuPG) 2.4.8", False),
    ("gpg (GnuPG) 2.5.14", True),
    ("gpg (GnuPG) 2.5.13", False),
    ("gpg (GnuPG) 2.3.7", False),
    ("gpg (GnuPG) 2.2.51", True),
    ("gpg (GnuPG) 2.2.36", False),
    ("gpg (GnuPG) 2.2.35", False),
    ("gpg (GnuPG) 2.6.0", True),
    ("gpg (GnuPG) 1.4.23", False),
    ("garbage", False),
    (None, False),
])
def test_the_floor_by_version(stub_version, monkeypatch, line, passes):
    monkeypatch.delenv(pgp.PATCHED_AS_ENV, raising=False)
    stub_version(line)
    assert (pgp._floor_problem("gpg") is None) is passes


def test_a_below_floor_or_unreadable_gpg_records_no_verifier(stub_version,
                                                             monkeypatch):
    monkeypatch.delenv(pgp.PATCHED_AS_ENV, raising=False)
    for line in ("gpg (GnuPG) 2.4.8", "gpg (GnuPG) 2.3.6", "garbage"):
        stub_version(line)
        result = verify_detached(BINARY_SIG, DATA, SUB_PUB,
                                 claimed_fingerprint=SUB_PRIMARY,
                                 confirms_value=TOX_PUBKEY)
        assert result.outcome == NO_VERIFIER, line
        assert result.verifier == "NONE"


def test_the_operator_attestation_admits_a_patched_distribution_build(
        stub_version, monkeypatch):
    """Ubuntu 24.04's 2.4.4-2ubuntu17.4 carries the fix and reports 2.4.4:
    refused without the attestation, admitted with it, and the attestation
    is on the recorded version."""
    stub_version("gpg (GnuPG) 2.4.4")
    monkeypatch.delenv(pgp.PATCHED_AS_ENV, raising=False)
    assert pgp._floor_problem("gpg") is not None
    monkeypatch.setenv(pgp.PATCHED_AS_ENV, "2.4.9")
    assert pgp._floor_problem("gpg") is None
    monkeypatch.setattr(pgp, "gpg_path", lambda: "gpg")
    assert "attested by the operator" in pgp.verifier_version()
    for wrong in ("2.5.14", "2.4.3", "2.4.8", "2.4"):
        monkeypatch.setenv(pgp.PATCHED_AS_ENV, wrong)
        assert pgp._floor_problem("gpg") is not None, wrong


def test_an_oversized_detached_input_never_reaches_a_subprocess(monkeypatch):
    _no_subprocess(monkeypatch)
    big_sig = verify_detached(b"\x88" * (pgp.MAX_SIGNATURE_BYTES + 1), DATA,
                              SUB_PUB, claimed_fingerprint=SUB_PRIMARY)
    big_data = verify_detached(BINARY_SIG, b"x" * (pgp.MAX_MESSAGE_BYTES + 1),
                               SUB_PUB, claimed_fingerprint=SUB_PRIMARY)
    assert big_sig.outcome == MALFORMED and big_data.outcome == MALFORMED
