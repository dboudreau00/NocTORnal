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


# The row-security binding proof (S1, 2026-09-25). A request's
# database connection is bound to its user by a value only the holder of
# the raw token can compute; the session row stores sha256 of it
# (iam.session.rls_binding_hash, migration 0110) and iam.rls_actor() finds
# the session by that. Not token_hash: token_hash is readable by the
# request role, so a binding keyed on it would let any reader of
# iam.session bind as any live session. The context separates this
# derivation from every other use of the token, so the proof is never the
# HTTP credential and a proof in a database log opens no API session.
RLS_PROOF_CONTEXT = b"noctornal-rls-v1\x00"


def rls_proof(raw_token: str) -> str:
    """What the request's connection presents (hex, so it travels as text
    in a setting)."""
    return hashlib.sha256(RLS_PROOF_CONTEXT + raw_token.encode("utf-8")).hexdigest()


def rls_binding_hash(raw_token: str) -> bytes:
    """What the session row stores: sha256 of the proof's UTF-8 text, the
    same bytes iam.rls_actor() hashes on the database side."""
    return hashlib.sha256(rls_proof(raw_token).encode("utf-8")).digest()


@dataclass(frozen=True)
class NewToken:
    raw: str        # returned to the client once, never stored
    hash: bytes     # stored in iam.session.token_hash
    # Stored in iam.session.rls_binding_hash (S1, 2026-09-25).
    rls_binding_hash: bytes | None = None


def new_session_token() -> NewToken:
    raw = secrets.token_urlsafe(_TOKEN_BYTES)
    return NewToken(raw=raw, hash=hash_token(raw),
                    rls_binding_hash=rls_binding_hash(raw))
