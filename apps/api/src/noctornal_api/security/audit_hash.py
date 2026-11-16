"""Keyed hashes of what the audit log records about who asked: a peer's address and the identifier a
failed sign-in typed, and the one keyed value a purge's dry run hands back.

The one place any is computed. All are HMAC-SHA256 under `NOCTORNAL_AUDIT_PEPPER`, a secret of its own, each behind a label of its own, so an
address hash and an identifier hash made from one value under one key are never equal and cannot be
compared with each other. An unkeyed sha256 of an address is no secret at all: IPv4 is 2^32 values, so a
table of every hash is an hour's work for anybody who can read the audit log, and a short typed password
falls the same way.

The length marks the scheme, so a row from before this module is told apart without a version column:
`ip_hash` is 16 bytes here and was a 32-byte plain sha256 before (`octet_length(ip_hash)`), and the
identifier is recorded as `email_hmac`, 16 hex characters, where the older rows carry `email_sha256`.
Those rows are history: `audit.event` is append-only and its chain hashes the value stored, so nothing
rewrites them, and they stay as guessable as they were.

No key, no hash, and never an unkeyed one. A production start refuses without a usable pepper
(`config.verify_environment`); should the pepper still be one `pepper_state` refuses when a row is written
(empty, short, or a copy of another secret, in a process that never ran that refusal), the hash is None,
and an error line names the variable and why, at most once a minute. In development an unset pepper is replaced by
a random key of this process's own, with one warning, so the hashes correlate only until the process
restarts (and not across uvicorn workers), and there is still no default value in code (CONVENTIONS:
Secrets).

The address hashed is the text `client_ip` returns, not canonicalised, as before: an IPv4-mapped IPv6
address and its plain IPv4 form hash differently.

Rotating the pepper is allowed and costs only correlation: rows written after it no longer match rows
written before it for the same address or identifier. Nothing stored breaks, unlike the ingest pepper. The
one other thing it voids is a purge preview not yet confirmed (`purge_preview_mac`), which is made again by
running the dry run again.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections.abc import Mapping
from typing import NamedTuple

from noctornal_api.config import is_production, published_credentials
from noctornal_api.wording import count_of

log = logging.getLogger("noctornal.audit_hash")

PEPPER_ENV = "NOCTORNAL_AUDIT_PEPPER"
#: The shortest pepper a production start accepts. scripts/production_secrets.py generates 43.
MIN_PEPPER_CHARS = 16
#: The secrets of other purposes the pepper must not be a copy of: one value pasted into two purposes
#: is one compromise and one rotation for both, which is what keeping them apart is for.
OTHER_SECRETS = ("NOCTORNAL_INGEST_PEPPER", "NOCTORNAL_TOTP_KEK")

#: 128 bits, half the old plain sha256, so the length alone says which scheme wrote a row.
IP_HASH_BYTES = 16
#: 64 bits: enough to tell repeated submissions apart in one bounded log, and with the key unknown no
#: length is guessable.
IDENT_HEX_CHARS = 16

_IP_LABEL = b"noctornal/audit/ip/v1\0"
_IDENT_LABEL = b"noctornal/audit/identifier/v1\0"
_PURGE_PREVIEW_LABEL = b"noctornal/retention/purge-preview/v1\0"

#: How often, at most, a production process with no pepper says so.
UNSET_LOG_SECONDS = 60.0

_lock = threading.Lock()
_development_key: bytes | None = None
_unset_said_at: float | None = None


class PepperState(NamedTuple):
    """What a process makes of its pepper. `why` is empty when `ok`, and names the variable and never
    its value; `length` is the stripped value's length in characters."""
    ok: bool
    length: int
    why: str


def pepper_state(env: Mapping[str, str] | None = None) -> PepperState:
    """The verdict on the pepper `env` (the process environment by default) carries: the one reader the
    boot refusal and the readiness row `audit_pepper_set` ask, so the two cannot disagree. Stripped, as
    the key is read. A published value is `config.published_credentials`'s to refuse, by the name."""
    source = os.environ if env is None else env
    raw = source.get(PEPPER_ENV, "").strip()
    if not raw:
        return PepperState(False, 0, f"{PEPPER_ENV} is not set")
    if len(raw) < MIN_PEPPER_CHARS:
        return PepperState(False, len(raw),
                           f"{PEPPER_ENV} is {count_of(len(raw), 'character', 'characters')}, "
                           f"fewer than {MIN_PEPPER_CHARS}")
    for other in OTHER_SECRETS:
        if raw == source.get(other, "").strip():
            return PepperState(False, len(raw), f"{PEPPER_ENV} is the same value as {other}")
    return PepperState(True, len(raw), "")


def _say_unusable(why: str) -> None:
    global _unset_said_at
    now = time.monotonic()
    with _lock:
        if _unset_said_at is not None and now - _unset_said_at < UNSET_LOG_SECONDS:
            return
        _unset_said_at = now
    log.error("%s in this production process, so the audit rows it writes carry no address or "
              "identifier hash and a purge's dry run issues no preview; set a usable %s in "
              "secrets.env and restart", why, PEPPER_ENV)


def _random_development_key() -> bytes:
    global _development_key
    with _lock:
        if _development_key is None:
            _development_key = secrets.token_bytes(32)
            log.warning("%s is not set, so this development process keys the audit hashes with a "
                        "random key of its own: they correlate only until it restarts", PEPPER_ENV)
        return _development_key


def _key() -> bytes | None:
    """The key, read on every call as `ingest._pepper` reads its own, so a test can set the variable.
    In production it is the pepper only when the boot refusal would take it (`pepper_state`, and no
    published value), so a process that never ran that refusal (a script that signs an operator in)
    cannot hash under a pepper the API would not start with: None otherwise, with the reason logged."""
    raw = os.environ.get(PEPPER_ENV, "").strip()
    if is_production():
        state = pepper_state()
        why = state.why if not state.ok else (
            f"{PEPPER_ENV} still carries a value somebody has published"
            if published_credentials({PEPPER_ENV: raw}) else "")
        if why:
            _say_unusable(why)
            return None
        return raw.encode("utf-8")
    if raw:
        return raw.encode("utf-8")
    return _random_development_key()


def _mac(key: bytes, label: bytes, text: str) -> bytes:
    # `surrogatepass`: a JSON body can carry a lone surrogate, which a hash must not turn into a 500.
    return hmac.new(key, label + text.encode("utf-8", "surrogatepass"), hashlib.sha256).digest()


def ip_hash(address: str | None) -> bytes | None:
    """The 16-byte keyed hash `audit.event.ip_hash` and `lab.download_ticket.ip_hash` record for
    `address`; None for no address, or for no key."""
    if not address:
        return None
    key = _key()
    return None if key is None else _mac(key, _IP_LABEL, address)[:IP_HASH_BYTES]


def identifier_hash(value: str) -> str | None:
    """The 16 hex characters a failed sign-in records as `email_hmac` for what was typed as the email;
    None for no key. A Security Officer who holds the pepper and suspects an address recomputes it:
    `hmac.new(pepper, b"noctornal/audit/identifier/v1\\0" + address.encode(), "sha256").hexdigest()[:16]`."""
    key = _key()
    return None if key is None else _mac(key, _IDENT_LABEL, value).hex()[:IDENT_HEX_CHARS]


def purge_preview_mac(material: str) -> str | None:
    """The 64 hex characters a purge's dry run hands back as its `preview`, and a real run must present
    again: HMAC-SHA256 of `material`, the canonical text of what was counted, under a subkey the pepper
    derives for this purpose alone. None for no key, and a caller then issues no preview and accepts none.

    The preview binds the irreversible act to the count the person confirmed, and covers every due item of
    the case, the ones above the caller included. An unkeyed digest of it is one the caller can rebuild from
    the items they are shown, which says whether something is left out and whether a remembered id was due.
    Keyed, it is the server's to make and to check, and nothing the caller holds reproduces it. A rotated
    pepper voids a preview not yet confirmed: the dry run is run again."""
    key = _key()
    if key is None:
        return None
    subkey = hmac.new(key, _PURGE_PREVIEW_LABEL, hashlib.sha256).digest()
    return hmac.new(subkey, material.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()


def typed_identifier(value: str) -> dict:
    """What a failed sign-in records of the value typed as the email: its length and `email_hmac`,
    never the value, whatever was typed and whether or not the account exists (docs/00 decision 237).

    The box is where a password is typed by mistake, and a password shaped like an address
    (`Hunter2@home.net`) cannot be told apart from an address, so nothing is kept as typed. The hash
    still tells repeated submissions apart, and whoever holds the pepper recomputes it for a candidate
    address, an account's own included. With no key only the length is recorded. The console's
    sign-in and the two scripts that sign an operator in (telegram_persona.py, egress_setup.py) all
    record through here; a script's development key is its own, so its hashes do not match the API's."""
    recorded: dict = {"email_length": len(value)}
    digest = identifier_hash(value)
    if digest is not None:
        recorded["email_hmac"] = digest
    return recorded
