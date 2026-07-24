"""Argon2id password hashing (docs/05: t=3, m=64 MiB, p=4)."""
import pytest

from noctornal_api.security import passwords


def test_hash_is_argon2id_and_not_plaintext():
    h = passwords.hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert "correct horse" not in h


def test_hash_is_salted_unique():
    a = passwords.hash_password("same-password")
    b = passwords.hash_password("same-password")
    assert a != b  # random salt per hash


def test_verify_roundtrip():
    h = passwords.hash_password("s3cret-pass")
    assert passwords.verify_password(h, "s3cret-pass") is True
    assert passwords.verify_password(h, "wrong-pass") is False


def test_verify_never_raises_on_garbage():
    assert passwords.verify_password("not-a-hash", "x") is False


def test_empty_password_rejected_at_hash_time():
    with pytest.raises(ValueError):
        passwords.hash_password("")


def test_configured_parameters():
    # t=3, m=64 MiB (65536 KiB), p=4 appear in the PHC string.
    h = passwords.hash_password("params")
    assert "m=65536" in h and "t=3" in h and "p=4" in h
