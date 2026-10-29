"""Argon2id password and recovery-code hashing.

Parameters per docs/05: t=3, m=64 MiB, p=4. No rotation policy, no
composition rules; breach-list checking is a set-time concern layered on
top (a hook is provided, the list itself is not bundled).
"""
from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# docs/05: Argon2id (t=3, m=64 MiB, p=4).
_PH = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # KiB → 64 MiB
    parallelism=4,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    """Return an Argon2id PHC-format hash. The salt is generated and
    embedded by argon2; never store or compare passwords in plaintext."""
    if not password:
        raise ValueError("password must not be empty")
    return _PH.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against an Argon2id hash. False on mismatch, and False (fast, no work) on a
    malformed or empty hash.

    Timing asymmetry: a malformed or empty hash returns in microseconds while a real hash costs the full
    Argon2id work. Callers that must not leak account existence or state must verify against a fixed valid
    dummy hash for unknown or no-password accounts (AuthService does) so every attempt does comparable work.
    """
    try:
        return _PH.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when the hash was made with weaker parameters than current —
    rehash opportunistically on the next successful login."""
    return _PH.check_needs_rehash(stored_hash)


# Recovery codes reuse the same KDF (docs/05: 10 single-use, Argon2id).
hash_recovery_code = hash_password
verify_recovery_code = verify_password
