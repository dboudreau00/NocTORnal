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


# --- the ring (2026-09-11) --------------------------------------------------
#
# `key_id` was written beside every blob and read by nothing: `decrypt`
# accepted it and used the one env key regardless. These pin that the id
# now SELECTS a key, that a retired key opens and never seals, and that
# the two ways a blob can fail to open are told apart by name.

import base64  # noqa: E402

_A = base64.b64encode(b"a" * 32).decode()
_B = base64.b64encode(b"b" * 32).decode()


def _ring(monkeypatch, *, active, active_id=None, retired=None):
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", active)
    if active_id is None:
        monkeypatch.delenv("NOCTORNAL_TOTP_KEK_ID", raising=False)
    else:
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK_ID", active_id)
    if retired is None:
        monkeypatch.delenv("NOCTORNAL_TOTP_KEK_RETIRED", raising=False)
    else:
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK_RETIRED", retired)


def test_the_active_key_records_its_id(monkeypatch):
    _ring(monkeypatch, active=_A)
    assert envelope.encrypt("x")[1] == "env:v1" == envelope.active_key_id()
    _ring(monkeypatch, active=_A, active_id="env:v2")
    assert envelope.encrypt("x")[1] == "env:v2"
    assert envelope.key_ids() == ("env:v2",)


def test_a_retired_key_still_opens_and_never_seals(monkeypatch):
    _ring(monkeypatch, active=_A)
    old_blob, old_id = envelope.encrypt("sealed under A")
    _ring(monkeypatch, active=_B, active_id="env:v2", retired=f"env:v1={_A}")
    assert envelope.key_ids() == ("env:v2", "env:v1")
    assert envelope.decrypt(old_blob, key_id=old_id) == "sealed under A"
    new_blob, new_id = envelope.encrypt("sealed under B")
    assert new_id == "env:v2"
    assert envelope.decrypt(new_blob, key_id=new_id) == "sealed under B"
    # A NULL id on a row means the pre-ring default, not the active key.
    assert envelope.decrypt(old_blob) == "sealed under A"


def test_an_unknown_key_id_is_named_and_carries_no_material(monkeypatch):
    _ring(monkeypatch, active=_A)
    blob, _ = envelope.encrypt("x")
    with pytest.raises(envelope.KeyUnavailable) as caught:
        envelope.decrypt(blob, key_id="env:v9")
    assert caught.value.key_id == "env:v9"
    assert "env:v9" in str(caught.value) and _A not in str(caught.value)
    assert isinstance(caught.value, envelope.UNOPENABLE)


def test_a_key_that_changed_under_its_own_id_is_reported_as_such(monkeypatch):
    """The defect the ring exists to name: same id, different key."""
    _ring(monkeypatch, active=_A)
    blob, key_id = envelope.encrypt("x")
    assert envelope.can_open(blob, key_id=key_id) is None
    _ring(monkeypatch, active=_B)                      # rotated, id unchanged
    problem = envelope.can_open(blob, key_id=key_id)
    assert problem and "does not open" in problem and "env:v1" in problem
    assert _A not in problem and _B not in problem
    _ring(monkeypatch, active=_B, active_id="env:v2")  # id moved, A not retired
    problem = envelope.can_open(blob, key_id=key_id)
    assert problem and "no key with id 'env:v1'" in problem


@pytest.mark.parametrize("retired, fragment", [
    (f"env:v1={_A}", "reuses the ACTIVE key id"),
    ("garbage", "entry 1 is not `id=base64`"),
    (f"env:v0={_A},env:v0={_A}", "twice"),
    ("env:v0=" + base64.b64encode(b"short").decode(), "32 bytes"),
    (f"env:v0={_A}, bad", "entry 2 is not `id=base64`"),
])
def test_a_malformed_ring_is_refused_by_position_never_by_value(
        monkeypatch, retired, fragment):
    _ring(monkeypatch, active=_A, retired=retired)
    with pytest.raises(RuntimeError) as caught:
        envelope.ring()
    assert fragment in str(caught.value), str(caught.value)
    assert _A not in str(caught.value)


def test_rewrap_moves_a_blob_to_the_active_key(monkeypatch):
    _ring(monkeypatch, active=_A)
    blob, key_id = envelope.encrypt("move me")
    _ring(monkeypatch, active=_B, active_id="env:v2", retired=f"env:v1={_A}")
    new_blob, new_id = envelope.rewrap(blob, key_id=key_id)
    assert new_id == "env:v2" and new_blob != blob
    _ring(monkeypatch, active=_B, active_id="env:v2")   # A dropped
    assert envelope.decrypt(new_blob, key_id=new_id) == "move me"
    assert envelope.can_open(blob, key_id=key_id)         # the old blob is gone for good
