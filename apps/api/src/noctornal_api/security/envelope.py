"""Field-level envelope encryption for secrets at rest (TOTP secrets,
and later persona credentials / egress endpoints — docs/05).

AES-256-GCM. The key-encrypting key comes from the environment
(NOCTORNAL_TOTP_KEK, base64, 32 bytes) — never a default in code
(repo convention). A KMS/Vault-backed provider replaces the env source
later without changing callers; the stored blob is nonce || ciphertext.
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12
_KEK_ENV = "NOCTORNAL_TOTP_KEK"


def _load_kek() -> bytes:
    raw = os.environ.get(_KEK_ENV)
    if not raw:
        raise RuntimeError(
            f"{_KEK_ENV} is not set — refusing to encrypt/decrypt secrets "
            "with a default key. Provide a base64-encoded 32-byte key "
            "(dev: `python -c \"import os,base64;"
            "print(base64.b64encode(os.urandom(32)).decode())\"`)."
        )
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError(f"{_KEK_ENV} must decode to 32 bytes, got {len(key)}")
    return key


def encrypt(plaintext: str, *, key_id: str = "env:v1") -> tuple[bytes, str]:
    """Return (nonce||ciphertext, key_id). key_id records which KEK sealed
    the blob so rotation can re-wrap only what a retired key holds."""
    kek = _load_kek()
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(kek).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct, key_id


def decrypt(blob: bytes, *, key_id: str = "env:v1") -> str:
    """Inverse of encrypt. Raises cryptography.exceptions.InvalidTag if
    the blob was tampered with or the wrong key is supplied."""
    kek = _load_kek()
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(kek).decrypt(nonce, ct, None).decode("utf-8")
