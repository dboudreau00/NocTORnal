"""RFC 6238 TOTP with ±1 window drift and replay protection.

docs/05: 30 s step, SHA-1 (authenticator compatibility), ±1 window.
Replay protection: the last accepted time-step counter is stored per user
and a code is rejected unless its counter is strictly greater. This is the
part frequently omitted and trivially exploitable — an attacker who
shoulder-surfs or phishes one 6-digit code has 30-90 s to replay it
otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

STEP_SECONDS = 30
DIGITS = 6
DRIFT_WINDOWS = 1  # ±1 step
_ALGORITHM = hashlib.sha1  # RFC 6238 default; required for authenticator apps


def generate_secret(num_bytes: int = 20) -> str:
    """A new base32 TOTP secret (RFC 4226 recommends >= 160 bits)."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii")


def _counter(timestamp: int) -> int:
    return timestamp // STEP_SECONDS


def _hotp(secret_b32: str, counter: int) -> str:
    # base32 secrets are stored without padding in some apps; restore it.
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, _ALGORITHM).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** DIGITS)).zfill(DIGITS)


def code_at(secret_b32: str, timestamp: int) -> str:
    """The TOTP code for the step containing `timestamp` (test/QR helper)."""
    return _hotp(secret_b32, _counter(timestamp))


@dataclass(frozen=True)
class TotpResult:
    ok: bool
    # The counter that must be persisted as the new last-accepted value on
    # success. None when the code did not verify.
    new_last_counter: int | None = None


def verify(
    secret_b32: str,
    code: str,
    timestamp: int,
    last_counter: int | None,
) -> TotpResult:
    """Verify `code` at `timestamp` within ±1 step, enforcing replay
    protection against `last_counter`.

    A candidate step counter is accepted only if it is strictly greater
    than `last_counter`, so a code already used (or any code from an
    earlier-or-equal step) cannot be replayed even inside its validity
    window. On success the caller MUST persist `new_last_counter`.
    """
    code = (code or "").strip()
    # isascii() first: str.isdigit() accepts non-ASCII digits (e.g. Arabic-
    # Indic), which hmac.compare_digest then rejects with TypeError — a
    # client-triggerable crash. Guard closes that DoS and keeps verify total.
    if len(code) != DIGITS or not code.isascii() or not code.isdigit():
        return TotpResult(False)

    current = _counter(timestamp)
    # Check the earliest drift step first so the smallest valid counter
    # wins; that maximises how many future steps replay protection covers.
    for delta in range(-DRIFT_WINDOWS, DRIFT_WINDOWS + 1):
        candidate = current + delta
        if candidate < 0:
            continue
        if last_counter is not None and candidate <= last_counter:
            continue  # already used, or superseded → replay
        if hmac.compare_digest(code, _hotp(secret_b32, candidate)):
            return TotpResult(True, candidate)
    return TotpResult(False)
