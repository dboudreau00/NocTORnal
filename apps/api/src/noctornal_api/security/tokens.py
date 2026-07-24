"""Opaque session tokens.

docs/05: the token is a high-entropy opaque string; only its hash is
stored, so a database read cannot reconstruct a live session. The raw
token is returned to the client exactly once.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

# 256 bits, URL-safe. __Host- prefix / cookie attributes are set by the
# HTTP layer, not here.
_TOKEN_BYTES = 32


def hash_token(raw_token: str) -> bytes:
    """SHA-256 of the raw token. Deterministic (it is the lookup key), so
    no per-token salt — the token itself carries 256 bits of entropy."""
    return hashlib.sha256(raw_token.encode("utf-8")).digest()


@dataclass(frozen=True)
class NewToken:
    raw: str        # returned to the client once, never stored
    hash: bytes     # stored in iam.session.token_hash


def new_session_token() -> NewToken:
    raw = secrets.token_urlsafe(_TOKEN_BYTES)
    return NewToken(raw=raw, hash=hash_token(raw))
