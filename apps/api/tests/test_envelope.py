"""AES-256-GCM envelope for TOTP secrets at rest (docs/05)."""

import pytest

from noctornal_api.security import envelope


def test_roundtrip():
    secret = "JBSWY3DPEHPK3PXP"
    blob, key_id = envelope.encrypt(secret)
    assert blob != secret.encode()
    assert envelope.decrypt(blob, key_id=key_id) == secret


def test_ciphertext_is_nondeterministic():
    a, _ = envelope.encrypt("same")
    b, _ = envelope.encrypt("same")
    assert a != b  # random nonce per encryption


def test_tamper_detected():
    from cryptography.exceptions import InvalidTag
    blob, _ = envelope.encrypt("secret")
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        envelope.decrypt(bytes(tampered))


def test_missing_kek_refuses(monkeypatch):
    monkeypatch.delenv("NOCTORNAL_TOTP_KEK", raising=False)
    with pytest.raises(RuntimeError, match="NOCTORNAL_TOTP_KEK"):
        envelope.encrypt("x")
